from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceSeal(BaseModel):
    sha256_hash: str
    byte_size: int
    sealed_at: str
    encoding: str = "raw_bytes"


class Decision(BaseModel):
    risk: str
    score: int = Field(ge=0, le=100)
    action: str
    confidence: int = Field(ge=0, le=100)
    reasons: List[str] = Field(default_factory=list)
    attack_classification: List[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    status: str
    case_id: str
    decision: Decision
    email: Dict[str, Any]
    authentication: Dict[str, Any]
    nlp_analysis: Dict[str, Any]
    ml_analysis: Dict[str, Any]
    url_intelligence: Dict[str, Any]
    domain_intelligence: Dict[str, Any]
    infrastructure: Dict[str, Any]
    threat_score: Dict[str, Any]
    evidence: List[str]
    ai_explanation: str
    evidence_seal: EvidenceSeal
    block_hash: str
