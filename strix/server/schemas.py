from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class Target(BaseModel):
    type: str
    target: str
    instruction: Optional[str] = None

class ScanRequest(BaseModel):
    run_name: Optional[str] = None
    targets: List[Target]
    user_instructions: Optional[str] = None
    model_name: str = "openai/gpt-5"

class AgentState(BaseModel):
    id: str
    name: str
    status: str
    current_step: Optional[str] = None

class ScanStatus(BaseModel):
    run_id: str
    status: str
    agents: List[AgentState]
    vulnerabilities_count: int
