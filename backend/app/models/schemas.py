"""
Pydantic request/response contracts for the gateway API.
Kept separate from ORM models (db/models.py) — Repository/Service layers
translate between the two so the API surface never leaks DB internals.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectedEntity(BaseModel):
    entity_type: str            # e.g. "AADHAAR", "EMAIL", "AWS_SECRET_KEY"
    value_preview: str          # masked preview, never the raw sensitive value
    start: Optional[int] = None
    end: Optional[int] = None
    confidence: float = 0.9
    source: str                 # which analyzer found it


class AnalyzerFinding(BaseModel):
    analyzer_name: str
    severity: Severity
    confidence: float
    evidence: List[str] = []
    entities: List[DetectedEntity] = []
    recommendation: Optional[str] = None
    passed: bool = True          # True = no issue found by this analyzer


class PolicyViolation(BaseModel):
    policy_name: str
    description: str
    triggered_by: List[str] = []  # entity types / analyzer names that triggered it


class AnalyzeRequest(BaseModel):
    prompt: str
    provider: Optional[str] = None
    model: Optional[str] = None
    session_id: Optional[str] = None


class AnalyzeResponse(BaseModel):
    request_id: str
    risk_score: int
    risk_level: RiskLevel
    decision: str                     # "ALLOW" | "BLOCK" | "WARN"
    send_enabled: bool
    findings: List[AnalyzerFinding]
    policy_violations: List[PolicyViolation]
    detected_entity_summary: Dict[str, int]
    recommendations: List[str]
    masked_prompt_preview: Optional[str] = None
    auto_fix_available: bool = False
    document_classifications: List[Dict[str, Any]] = []
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


class SendRequest(BaseModel):
    request_id: str                   # must match a prior /analyze call
    prompt: str
    provider: Optional[str] = None
    model: Optional[str] = None
    use_masked_version: bool = False


class SendResponse(BaseModel):
    response_text: str
    provider_used: str
    model_used: str
    output_flags: List[AnalyzerFinding] = []
    was_sanitized: bool = False


class MaskRequest(BaseModel):
    prompt: str


class MaskResponse(BaseModel):
    masked_prompt: str
    entities_masked: int


class AuditLogEntry(BaseModel):
    id: int
    request_id: str
    timestamp: datetime
    decision: str
    risk_score: int
    risk_level: RiskLevel
    entity_types: List[str]
    provider: Optional[str]
    model: Optional[str]
    user: Optional[str] = "local-user"

    class Config:
        from_attributes = True
