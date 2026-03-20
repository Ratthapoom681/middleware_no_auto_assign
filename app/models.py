from pydantic import BaseModel, Extra
from typing import Any, Dict, List, Optional

class WazuhRule(BaseModel, extra=Extra.ignore):
    id: str
    level: int
    description: str
    groups: List[str] = []

class WazuhAgent(BaseModel, extra=Extra.ignore):
    id: str
    name: str
    ip: Optional[str] = None

class WazuhAlert(BaseModel, extra=Extra.ignore):
    id: str
    timestamp: str
    rule: WazuhRule
    agent: WazuhAgent
    manager: Optional[Dict[str, Any]] = None
    decoder: Optional[Dict[str, Any]] = None
    location: Optional[str] = "unknown"
    full_log: Optional[str] = ""
    data: Optional[Dict[str, Any]] = {} 
    
    # Capture raw JSON
    raw_payload: Dict[str, Any] = {}
