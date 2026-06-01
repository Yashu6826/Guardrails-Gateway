from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    TRANSFORM = "transform"


class ContextDoc(BaseModel):
    id: str = Field(..., max_length=256)
    text: str = Field(..., max_length=50000)


class Metadata(BaseModel):
    app_id: str = Field(..., max_length=256)
    user_id: str = Field(..., max_length=256)
    request_id: str = Field(..., max_length=256)


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., max_length=10000)
    context_docs: Optional[List[ContextDoc]] = Field(default=[], max_length=3)
    metadata: Metadata


class AnalyzeResponse(BaseModel):
    decision: Decision
    risk_score: int = Field(..., ge=0, le=100)
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[ContextDoc]
    reasons: List[Dict[str, str]] = []


class PolicyResponse(BaseModel):
    version: str
    detectors: List[str]
    thresholds: Dict[str, int]