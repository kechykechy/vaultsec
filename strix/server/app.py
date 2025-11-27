import asyncio
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List

import logging

from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from strix.server.schemas import ScanRequest, ScanStatus
from strix.server.ws_manager import manager
from strix.server.live_tracer import LiveTracer
from strix.server.reporting import generate_html_report
from strix.telemetry.tracer import get_global_tracer, set_global_tracer
from strix.agents.VaultAgent.vault_agent import VaultAgent
from strix.llm.config import LLMConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Strix API")


@app.get("/")
async def root():
    """Redirect root to UI"""
    return RedirectResponse(url="/ui")


BASE_DIR = Path(__file__).resolve().parents[2]
UI_DIR = BASE_DIR / "ui"
RUNS_DIR = BASE_DIR / "agent_runs"
RUNS_DIR.mkdir(exist_ok=True)

if UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")
else:
    logger.warning("UI directory not found at %s; /ui endpoint disabled", UI_DIR)

app.mount("/runs", StaticFiles(directory=RUNS_DIR), name="runs")

# Allow CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
current_scan_task: asyncio.Task | None = None
scan_lock = asyncio.Lock()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, maybe handle client messages
            await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    global current_scan_task
    
    async with scan_lock:
        if current_scan_task and not current_scan_task.done():
            raise HTTPException(status_code=400, detail="A scan is already running")

        # Initialize Tracer
        run_name = request.run_name or f"run-{os.urandom(4).hex()}"
        tracer = LiveTracer(run_name=run_name)
        set_global_tracer(tracer)
        
        # Configure Agent
        agent_config = {
            "llm_config": LLMConfig(), # Uses env vars
            "max_iterations": 300
        }
        
        # Prepare Scan Config for tracing (API-level view)
        scan_config = {
            "scan_id": run_name,
            "targets": [t.dict() for t in request.targets],  # Convert pydantic models to dicts
            "user_instructions": request.user_instructions or "",
            "run_name": run_name,
        }

        # Store the original configuration on the tracer so it can be used as a "memory"
        tracer.set_scan_config(scan_config)

        # Provide a shallow copy for the agent so it can freely mutate targets
        scan_config_for_agent: Dict[str, Any] = {
            "scan_id": scan_config["scan_id"],
            "targets": [t.copy() for t in scan_config["targets"]],
            "user_instructions": scan_config["user_instructions"],
            "run_name": scan_config["run_name"],
        }
        
        # Start Scan in Background
        # We create a task to run it in the event loop
        current_scan_task = asyncio.create_task(run_agent_scan(agent_config, scan_config_for_agent))
        
        return {"status": "started", "run_id": run_name}

@app.post("/api/scan/stop")
async def stop_scan():
    global current_scan_task
    if current_scan_task and not current_scan_task.done():
        current_scan_task.cancel()
        try:
            await current_scan_task
        except asyncio.CancelledError:
            pass
        
        # Cleanup
        tracer = get_global_tracer()
        if tracer:
            tracer.cleanup()
            
        return {"status": "stopped"}
    return {"status": "no_scan_running"}

@app.get("/api/scan/status")
async def get_status():
    tracer = get_global_tracer()
    if not tracer:
        return {"status": "idle"}
        
    agents_data = []
    for agent_id, data in tracer.agents.items():
        agents_data.append({
            "id": agent_id,
            "name": data.get("name", "Unknown"),
            "status": data.get("status", "unknown"),
        })
        
    return {
        "run_id": tracer.run_id,
        "status": "running" if current_scan_task and not current_scan_task.done() else "completed",
        "agents": agents_data,
        "vulnerabilities_count": len(tracer.vulnerability_reports)
    }

@app.get("/api/scan/report", response_class=HTMLResponse)
async def get_report():
    tracer = get_global_tracer()
    if not tracer:
        return HTMLResponse(content="<h1>No scan data available</h1>", status_code=404)
    
    # Reconstruct history suitable for the report
    history = []
    
    # Add tools (we only care about tools with screenshots for the audit log visual section, but let's pass them all)
    for exec_id, tool in tracer.tool_executions.items():
        item = {
            "type": "tool",
            "tool_name": tool["tool_name"],
            "args": tool["args"],
            "result": tool.get("result"),
            "status": tool.get("status"),
            "timestamp": tool.get("timestamp"),
            "screenshot_url": None
        }
        
        res = tool.get("result")
        if isinstance(res, dict) and isinstance(res.get("screenshot"), str) and res["screenshot"].startswith("file://"):
             # Extract filename
             # file:///.../agent_runs/run-id/screenshots/exec_X.png
             path_str = res["screenshot"].replace("file://", "")
             path = Path(path_str)
             run_id = tracer.run_name or tracer.run_id
             item["screenshot_url"] = f"/runs/{run_id}/screenshots/{path.name}"
             
        history.append(item)
        
    # Generate HTML
    html_content = generate_html_report(
        run_data=tracer.run_metadata,
        vulnerabilities=tracer.vulnerability_reports,
        history=history
    )
    
    return html_content


@app.get("/api/runs")
async def list_runs():
    """List saved scan runs (memories) from the agent_runs directory."""
    runs: List[Dict[str, Any]] = []

    try:
        for run_dir in sorted(RUNS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not run_dir.is_dir():
                continue

            snapshot_path = run_dir / "run.json"
            if snapshot_path.exists():
                try:
                    with snapshot_path.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                    meta = data.get("run_metadata", {})
                    runs.append(
                        {
                            "run_id": meta.get("run_id") or run_dir.name,
                            "run_name": meta.get("run_name") or run_dir.name,
                            "start_time": meta.get("start_time"),
                            "end_time": meta.get("end_time"),
                            "status": meta.get("status", "completed"),
                            "duration_seconds": meta.get("duration_seconds"),
                            "vulnerabilities_count": meta.get(
                                "vulnerabilities_count",
                                len(data.get("vulnerability_reports", [])),
                            ),
                            "agents_count": meta.get(
                                "agents_count", len(data.get("agents", {}))
                            ),
                            "targets": meta.get("targets", []),
                            "storage_id": run_dir.name,
                        }
                    )
                except Exception as e:  # noqa: BLE001
                    logger.warning(
                        "Failed to read run snapshot %s: %s", snapshot_path, e
                    )
            else:
                # Older runs without snapshots – still surface minimal info
                runs.append(
                    {
                        "run_id": run_dir.name,
                        "run_name": run_dir.name,
                        "start_time": None,
                        "end_time": None,
                        "status": "unknown",
                        "duration_seconds": None,
                        "vulnerabilities_count": 0,
                        "agents_count": 0,
                        "targets": [],
                        "storage_id": run_dir.name,
                    }
                )
    except Exception:  # noqa: BLE001
        logger.exception("Failed to list runs")
        raise HTTPException(status_code=500, detail="Failed to list runs")

    return {"runs": runs}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str):
    """Return the full JSON snapshot for a given run."""
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists() or not run_dir.is_dir():
        raise HTTPException(status_code=404, detail="Run not found")

    snapshot_path = run_dir / "run.json"
    if not snapshot_path.exists():
        raise HTTPException(status_code=404, detail="Run snapshot not found")

    try:
        with snapshot_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001
        logger.exception("Failed to read run snapshot for %s", run_id)
        raise HTTPException(status_code=500, detail="Failed to read run snapshot")

    return data


@app.get("/api/runs/{run_id}/report", response_class=HTMLResponse)
async def get_run_report(run_id: str):
    """Generate an HTML report for a completed run using its stored snapshot."""
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists() or not run_dir.is_dir():
        return HTMLResponse(content="<h1>Run not found</h1>", status_code=404)

    snapshot_path = run_dir / "run.json"
    if not snapshot_path.exists():
        return HTMLResponse(content="<h1>Run snapshot not found</h1>", status_code=404)

    try:
        with snapshot_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001
        logger.exception("Failed to read run snapshot for report: %s", run_id)
        return HTMLResponse(
            content="<h1>Failed to load run snapshot</h1>", status_code=500
        )

    run_data = data.get("run_metadata", {})
    vulnerabilities = data.get("vulnerability_reports", [])

    history: List[Dict[str, Any]] = []
    tool_executions = data.get("tool_executions", {}) or {}
    for exec_data in tool_executions.values():
        history.append(
            {
                "type": "tool",
                "tool_name": exec_data.get("tool_name"),
                "args": exec_data.get("args"),
                "result": exec_data.get("result"),
                "status": exec_data.get("status"),
                "timestamp": exec_data.get("timestamp"),
                "screenshot_url": exec_data.get("screenshot_url"),
                "local_screenshot_path": exec_data.get("local_screenshot_path"),
            }
        )

    html_content = generate_html_report(
        run_data=run_data,
        vulnerabilities=vulnerabilities,
        history=history,
    )

    return HTMLResponse(content=html_content)

async def run_agent_scan(agent_config: Dict[str, Any], scan_config: Dict[str, Any]):
    try:
        logger.info("Starting VaultAgent Scan...")
        # Reformat targets to match what VaultAgent expects
        # The API receives: targets: [{type: "url", target: "...", instruction: "..."}]
        # VaultAgent expects: targets: [{type: "web_application", details: {target_url: "..."}}]
        
        formatted_targets = []
        for t in scan_config["targets"]:
            if t["type"] == "url" or t["type"] == "web_application":
                formatted_targets.append({
                    "type": "web_application",
                    "details": {"target_url": t["target"]}
                })
            elif t["type"] == "repo" or t["type"] == "repository":
                 formatted_targets.append({
                    "type": "repository",
                    "details": {"target_repo": t["target"]}
                })
            # Add other types as needed
            
        scan_config["targets"] = formatted_targets
        
        agent = VaultAgent(agent_config)
        await agent.execute_scan(scan_config)
        
    except asyncio.CancelledError:
        logger.info("Scan cancelled by user")
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        tracer = get_global_tracer()
        if tracer:
            tracer.set_final_scan_result(f"Scan failed: {str(e)}", success=False)
    finally:
        tracer = get_global_tracer()
        if tracer:
            tracer.cleanup()
