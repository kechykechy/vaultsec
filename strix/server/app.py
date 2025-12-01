import asyncio
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Dict, List

import logging

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, WebSocket, status
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
from strix.server.database import (
    init_db,
    create_user,
    get_user_by_username,
    get_user_by_email,
    authenticate_user,
    create_scan,
    update_scan_status,
    get_user_scans,
    get_user_running_scan,
    get_scan_by_storage_id,
    user_owns_scan,
)
from strix.server.auth import (
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
    create_access_token,
    get_current_user,
    get_current_user_optional,
    decode_token,
    CurrentUser,
    OptionalUser,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="VaultSec API")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()
    logger.info("Database initialized")


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
async def websocket_endpoint(websocket: WebSocket, token: str | None = None):
    """WebSocket endpoint with user authentication via token query param."""
    # Authenticate user from token
    user_id = None
    if token:
        token_data = decode_token(token)
        if token_data and token_data.user_id:
            user_id = token_data.user_id
    
    if not user_id:
        await websocket.close(code=4001, reason="Authentication required")
        return
    
    await manager.connect(websocket, user_id)
    try:
        while True:
            # Keep connection alive, handle client messages
            await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.post("/api/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    """Register a new user."""
    # Check if username exists
    if get_user_by_username(user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    
    # Check if email exists
    if get_user_by_email(user_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    try:
        user = create_user(
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
        )
        return UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            is_admin=user["is_admin"],
            created_at=user["created_at"],
        )
    except sqlite3.IntegrityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User registration failed",
        ) from e


@app.post("/api/auth/login", response_model=Token)
async def login(credentials: UserLogin):
    """Login and get an access token."""
    user = authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(
        data={"sub": user["id"], "username": user["username"]}
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser):
    """Get the current authenticated user."""
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        is_admin=bool(current_user.get("is_admin", False)),
        created_at=current_user["created_at"],
    )


# ============================================================================
# Scan Endpoints (User-Scoped)
# ============================================================================

# Track scans per user
user_scan_tasks: Dict[str, asyncio.Task] = {}
user_scan_db_ids: Dict[str, str] = {}  # user_id -> scan db id


@app.post("/api/scan/start")
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser,
):
    """Start a new scan for the authenticated user."""
    user_id = current_user["id"]
    
    async with scan_lock:
        # Check if this user already has a running scan
        if user_id in user_scan_tasks and not user_scan_tasks[user_id].done():
            raise HTTPException(status_code=400, detail="You already have a scan running")

        # Initialize Tracer with user_id for targeted WebSocket updates
        run_name = request.run_name or f"run-{os.urandom(4).hex()}"
        storage_id = run_name  # The folder name in agent_runs
        tracer = LiveTracer(run_name=run_name, user_id=user_id)
        set_global_tracer(tracer)
        
        # Create scan record in database
        targets_json = json.dumps([t.dict() for t in request.targets])
        db_scan = create_scan(
            user_id=user_id,
            run_name=run_name,
            storage_id=storage_id,
            targets=targets_json,
            user_instructions=request.user_instructions,
        )
        user_scan_db_ids[user_id] = db_scan["id"]
        
        # Configure Agent
        agent_config = {
            "llm_config": LLMConfig(),  # Uses env vars
            "max_iterations": 300,
        }
        
        # Prepare Scan Config for tracing (API-level view)
        scan_config = {
            "scan_id": run_name,
            "targets": [t.dict() for t in request.targets],
            "user_instructions": request.user_instructions or "",
            "run_name": run_name,
            "user_id": user_id,  # Track which user owns this scan
        }

        # Store the original configuration on the tracer
        tracer.set_scan_config(scan_config)

        # Provide a shallow copy for the agent
        scan_config_for_agent: Dict[str, Any] = {
            "scan_id": scan_config["scan_id"],
            "targets": [t.copy() for t in scan_config["targets"]],
            "user_instructions": scan_config["user_instructions"],
            "run_name": scan_config["run_name"],
        }
        
        # Start Scan in Background
        task = asyncio.create_task(
            run_agent_scan(agent_config, scan_config_for_agent, user_id, db_scan["id"])
        )
        user_scan_tasks[user_id] = task
        
        return {"status": "started", "run_id": run_name, "scan_id": db_scan["id"]}

@app.post("/api/scan/stop")
async def stop_scan(current_user: CurrentUser):
    """Stop the current user's running scan."""
    user_id = current_user["id"]
    
    if user_id not in user_scan_tasks or user_scan_tasks[user_id].done():
        return {"status": "no_scan_running"}
    
    task = user_scan_tasks[user_id]
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    
    # Cleanup tracer
    tracer = get_global_tracer()
    scan_id = None
    if tracer:
        scan_id = tracer.run_id
        tracer.cleanup()
    
    # Update scan status in database
    if user_id in user_scan_db_ids:
        update_scan_status(
            user_scan_db_ids[user_id],
            "stopped",
            datetime.now(timezone.utc).isoformat(),
        )
        del user_scan_db_ids[user_id]
    
    # Stop and remove Docker sandbox containers
    await _cleanup_scan_containers(scan_id)
    
    # Clean up task reference
    del user_scan_tasks[user_id]
    
    return {"status": "stopped"}


async def _cleanup_scan_containers(scan_id: str | None = None) -> None:
    """Stop and remove Docker sandbox containers for the scan."""
    try:
        import docker
        client = docker.from_env()
        
        # Find containers by label
        filters = {"label": "strix-scan-id"}
        if scan_id:
            filters = {"label": f"strix-scan-id={scan_id}"}
        
        containers = client.containers.list(all=True, filters=filters)
        
        for container in containers:
            try:
                logger.info(f"Stopping scan container: {container.name}")
                container.stop(timeout=5)
                container.remove(force=True)
                logger.info(f"Removed scan container: {container.name}")
            except Exception as e:
                logger.warning(f"Failed to stop/remove container {container.name}: {e}")
                
    except Exception as e:
        logger.warning(f"Failed to cleanup scan containers: {e}")

@app.get("/api/scan/status")
async def get_status(current_user: CurrentUser):
    """Get the current scan status for the authenticated user."""
    user_id = current_user["id"]
    
    # Check if user has a running scan
    if user_id not in user_scan_tasks or user_scan_tasks[user_id].done():
        return {"status": "idle"}
    
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
        "status": "running",
        "agents": agents_data,
        "vulnerabilities_count": len(tracer.vulnerability_reports)
    }

@app.get("/api/scan/report", response_class=HTMLResponse)
async def get_report(current_user: CurrentUser):
    """Get the current scan report for the authenticated user."""
    user_id = current_user["id"]
    
    # Check if user has a running scan
    if user_id not in user_scan_tasks:
        return HTMLResponse(content="<h1>No scan data available</h1>", status_code=404)
    
    tracer = get_global_tracer()
    if not tracer:
        return HTMLResponse(content="<h1>No scan data available</h1>", status_code=404)
    
    # Reconstruct history suitable for the report
    history = []
    
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
             path_str = res["screenshot"].replace("file://", "")
             path = Path(path_str)
             run_id = tracer.run_name or tracer.run_id
             item["screenshot_url"] = f"/runs/{run_id}/screenshots/{path.name}"
             
        history.append(item)
        
    html_content = generate_html_report(
        run_data=tracer.run_metadata,
        vulnerabilities=tracer.vulnerability_reports,
        history=history
    )
    
    return html_content


@app.get("/api/runs")
async def list_runs(current_user: CurrentUser):
    """List saved scan runs for the authenticated user."""
    user_id = current_user["id"]
    
    # Get user's scans from database
    user_scans = get_user_scans(user_id)
    user_storage_ids = {scan["storage_id"] for scan in user_scans}
    
    runs: List[Dict[str, Any]] = []

    try:
        for run_dir in sorted(RUNS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not run_dir.is_dir():
                continue
            
            # Only show runs that belong to this user
            if run_dir.name not in user_storage_ids:
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
                # Older runs without snapshots
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
async def get_run(run_id: str, current_user: CurrentUser):
    """Return the full JSON snapshot for a given run (user must own it)."""
    user_id = current_user["id"]
    
    # Check if user owns this run
    if not user_owns_scan(user_id, run_id):
        raise HTTPException(status_code=403, detail="You don't have access to this run")
    
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
async def get_run_report(run_id: str, current_user: CurrentUser):
    """Generate an HTML report for a completed run (user must own it)."""
    user_id = current_user["id"]
    
    # Check if user owns this run
    if not user_owns_scan(user_id, run_id):
        return HTMLResponse(content="<h1>Access denied</h1>", status_code=403)
    
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

async def run_agent_scan(
    agent_config: Dict[str, Any],
    scan_config: Dict[str, Any],
    user_id: str,
    db_scan_id: str,
):
    """Run the agent scan and update database on completion."""
    try:
        logger.info("Starting VaultAgent Scan for user %s...", user_id)
        
        # Reformat targets to match what VaultAgent expects
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
            
        scan_config["targets"] = formatted_targets
        
        agent = VaultAgent(agent_config)
        await agent.execute_scan(scan_config)
        
        # Mark scan as completed in database
        update_scan_status(db_scan_id, "completed", datetime.now(timezone.utc).isoformat())
        
    except asyncio.CancelledError:
        logger.info("Scan cancelled by user %s", user_id)
        update_scan_status(db_scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
    except Exception as e:
        logger.error(f"Scan failed for user {user_id}: {e}", exc_info=True)
        update_scan_status(db_scan_id, "failed", datetime.now(timezone.utc).isoformat())
        tracer = get_global_tracer()
        if tracer:
            tracer.set_final_scan_result(f"Scan failed: {str(e)}", success=False)
    finally:
        tracer = get_global_tracer()
        if tracer:
            tracer.cleanup()
        
        # Clean up user scan tracking
        if user_id in user_scan_tasks:
            del user_scan_tasks[user_id]
        if user_id in user_scan_db_ids:
            del user_scan_db_ids[user_id]
