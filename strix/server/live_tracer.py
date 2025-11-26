import asyncio
from typing import Any
from strix.telemetry.tracer import Tracer
from strix.server.ws_manager import manager

class LiveTracer(Tracer):
    def __init__(self, run_name: str | None = None):
        super().__init__(run_name)
        
    def log_agent_creation(self, agent_id: str, name: str, task: str, parent_id: str | None = None) -> None:
        super().log_agent_creation(agent_id, name, task, parent_id)
        self._broadcast_update("agent_created", {
            "agent_id": agent_id,
            "name": name,
            "task": task,
            "parent_id": parent_id,
            "status": "running"
        })

    def update_agent_status(self, agent_id: str, status: str, error_message: str | None = None) -> None:
        super().update_agent_status(agent_id, status, error_message)
        self._broadcast_update("agent_status", {
            "agent_id": agent_id,
            "status": status,
            "error_message": error_message
        })

    def log_chat_message(self, content: str, role: str, agent_id: str | None = None, metadata: dict[str, Any] | None = None) -> int:
        msg_id = super().log_chat_message(content, role, agent_id, metadata)
        self._broadcast_update("chat_message", {
            "message_id": msg_id,
            "content": content,
            "role": role,
            "agent_id": agent_id,
            "timestamp": self.chat_messages[-1]["timestamp"],
            "metadata": metadata
        })
        return msg_id

    def log_tool_execution_start(self, agent_id: str, tool_name: str, args: dict[str, Any]) -> int:
        exec_id = super().log_tool_execution_start(agent_id, tool_name, args)
        self._broadcast_update("tool_start", {
            "execution_id": exec_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "args": args,
            "timestamp": self.tool_executions[exec_id]["timestamp"]
        })
        return exec_id

    def update_tool_execution(self, execution_id: int, status: str, result: Any | None = None) -> None:
        super().update_tool_execution(execution_id, status, result)
        
        # Check for screenshots in result
        screenshot_path = None
        if isinstance(result, dict) and "screenshot" in result:
            screenshot_data = result["screenshot"]
            # Basic check if it looks like base64
            if isinstance(screenshot_data, str) and len(screenshot_data) > 100: 
                screenshot_path = self._save_screenshot(execution_id, screenshot_data)
                # Update result to reference file instead of huge base64 string for memory/logs
                result["screenshot"] = f"file://{screenshot_path}" 

        # Handle potential binary/large data in result before broadcasting
        safe_result = str(result)
        if len(safe_result) > 5000:
            safe_result = safe_result[:5000] + "... (truncated)"
            
        broadcast_data = {
            "execution_id": execution_id,
            "status": status,
            "result": safe_result
        }
        
        if screenshot_path:
            # Assuming app mounts 'agent_runs' at '/runs'
            # screenshot_path is .../agent_runs/<run_id>/screenshots/exec_X.png
            # We want /runs/<run_id>/screenshots/exec_X.png
            run_id = self.run_name or self.run_id
            web_url = f"/runs/{run_id}/screenshots/{screenshot_path.name}"
            
            broadcast_data["screenshot_url"] = web_url
            
            # IMPORTANT: Update the Tracer's persistent storage so reports can find it
            if execution_id in self.tool_executions:
                self.tool_executions[execution_id]["screenshot_url"] = web_url
                self.tool_executions[execution_id]["local_screenshot_path"] = str(screenshot_path)

        self._broadcast_update("tool_end", broadcast_data)

    def _save_screenshot(self, execution_id: int, b64_data: str) -> Any:
        import base64
        from pathlib import Path
        
        try:
            run_dir = self.get_run_dir()
            screenshots_dir = run_dir / "screenshots"
            screenshots_dir.mkdir(exist_ok=True)
            
            filename = f"exec_{execution_id}.png"
            file_path = screenshots_dir / filename
            
            with open(file_path, "wb") as f:
                f.write(base64.b64decode(b64_data))
                
            return file_path
        except Exception as e:
            print(f"Failed to save screenshot: {e}")
            return None

    def add_vulnerability_report(self, title: str, content: str, severity: str) -> str:
        report_id = super().add_vulnerability_report(title, content, severity)
        self._broadcast_update("vulnerability", {
            "id": report_id,
            "title": title,
            "severity": severity,
            "content": content,
            "timestamp": self.vulnerability_reports[-1]["timestamp"]
        })
        return report_id

    def _broadcast_update(self, type: str, data: dict[str, Any]):
        # We need to run this in the event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(manager.broadcast({
                    "type": type,
                    "data": data
                }))
        except RuntimeError:
            # No event loop running
            pass
