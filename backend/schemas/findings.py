from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from pydantic import BaseModel, Field


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    category: str
    rule: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)


class EvidenceRecord(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    sha256: str
    byte_size: int = Field(ge=0)
    ingested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    analysis_version: str
    source_type: str = "eml"


class AnalysisResult(BaseModel):
    email_id: str
    evidence: EvidenceRecord
    classification: str
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    findings: List[Finding] = Field(default_factory=list)
    parsed: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
