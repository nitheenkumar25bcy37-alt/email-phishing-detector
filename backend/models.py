"""
Pydantic response models for Agentic MX API
Provides type safety and schema validation for all endpoints
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class EvidenceSeal(BaseModel):
    """SHA-256 evidence hash and metadata"""
    sha256_hash: str
    byte_size: int
    sealed_at: str
    encoding: str = "utf-8"


class MetadataInfo(BaseModel):
    """Email metadata extraction"""
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    received_count: int = 0


class MLAssessment(BaseModel):
    """Machine learning classification result"""
    model: str = "tfidf_logistic_regression"
    classification: str  # "phishing" or "legitimate"
    confidence_score: float = Field(..., ge=0, le=100)
    phishing_probability: float = Field(..., ge=0, le=100)
    class_probabilities: Dict[str, float] = {}


class URLIntelligence(BaseModel):
    """URL analysis results (placeholder for BATCH 2)"""
    urls_found: List[str] = []
    suspicious_urls: List[Dict[str, Any]] = []
    risk_score: int = 0
    risk_level: str = "LOW"


class DomainIntelligence(BaseModel):
    """Domain security analysis"""
    domain: Optional[str] = None
    mx_valid: Optional[bool] = None
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    domain_age_days: Optional[int] = None
    risk_flags: List[str] = []


class AuthenticationResult(BaseModel):
    """Email authentication verification (placeholder for BATCH 2)"""
    spf_status: str = "UNKNOWN"  # PASS, FAIL, NEUTRAL, NONE, UNKNOWN
    dkim_status: str = "UNKNOWN"
    dmarc_status: str = "UNKNOWN"
    authenticated: bool = False
    anomalies: List[str] = []


class NLPIndicator(BaseModel):
    """NLP-detected social engineering pattern"""
    category: str
    matched_phrases: List[str] = []
    severity: str = "LOW"  # LOW, MEDIUM, HIGH


class NLPIndicators(BaseModel):
    """All NLP indicators for an email"""
    indicators: List[NLPIndicator] = []
    total_severity_score: int = 0


class ThreatScore(BaseModel):
    """Deterministic 0-100 threat scoring"""
    total_score: int = Field(..., ge=0, le=100)
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    breakdown: Dict[str, int] = {}  # Component scores
    primary_signals: List[str] = []  # Top 3 reasons


class RoutingForensics(BaseModel):
    """Email routing and infrastructure analysis"""
    origin_ip: Optional[str] = None
    origin_country: Optional[str] = None
    origin_provider: Optional[str] = None
    hop_count: int = 0
    unusual_routing: bool = False
    routing_anomalies: List[str] = []


class AIBriefing(BaseModel):
    """LLM-generated forensic investigation"""
    executive_threat_assessment: str = ""
    attack_vector_identified: str = ""
    key_evidence: List[str] = []
    recommended_analyst_action: str = ""
    confidence_note: str = ""
    infrastructure_verdict: str = ""


class ThreatReport(BaseModel):
    """Complete threat analysis report"""
    success: bool
    error: Optional[str] = None
    report: Optional[Dict[str, Any]] = None


class AnalysisResponse(BaseModel):
    """Full API response for email analysis"""
    success: bool
    error: Optional[str] = None
    report: Optional[Dict[str, Any]] = None

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "report": {
                    "evidence_seal": {
                        "sha256_hash": "abc123...",
                        "byte_size": 1024,
                        "sealed_at": "2026-08-28T10:30:00Z"
                    },
                    "metadata": {
                        "from_address": "sender@example.com",
                        "subject": "Test email"
                    },
                    "threat_score": {
                        "total_score": 65,
                        "risk_level": "HIGH"
                    }
                }
            }
        }


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    version: str = "2.0.0"
    modules: Dict[str, str] = {}
    timestamp: str = ""
