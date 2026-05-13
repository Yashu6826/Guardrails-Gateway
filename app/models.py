from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    TRANSFORM = "transform"

class ContextDoc(BaseModel):
    id: str
    text: str

class Metadata(BaseModel):
    app_id: str
    user_id: str
    request_id: str

class AnalyzeRequest(BaseModel):
    prompt: str
    context_docs: Optional[List[ContextDoc]] = []
    metadata: Metadata

class AnalyzeResponse(BaseModel):
    decision: Decision
    risk_score: float
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[ContextDoc]
    raw_response: Optional[Dict[str, Any]] = None

class PolicyResponse(BaseModel):
    policies: Dict[str, Any]
    version: str