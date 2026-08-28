"""
Agentic MX - Data Models & Pydantic Schemas
Defines structured response shapes for API responses and component communications.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class EvidenceSeal(BaseModel):
    sha256_hash: str
    byte_size: int
    sealed_at: str
    encoding: str = "utf-8"

class Metadata(BaseModel):
    from_address: str = ""
    to_address: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_count: int = 0
    attachment_count: int = 0
    is_multipart: bool = False

class ScoreBreakdown(BaseModel):
    ml_score: float = 0.0
    nlp_score: float = 0.0
    url_score: float = 0.0
    domain_score: float = 0.0
    auth_score: float = 0.0
    infra_score: float = 0.0

class ThreatScore(BaseModel):
    score: int = Field(ge=0, le=100)
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    breakdown: ScoreBreakdown
    evidence_factors: List[str] = []

class MLAssessment(BaseModel):
    model: str = "TF-IDF + LogisticRegression"
    classification: str = "BENIGN"
    confidence_score: float = 0.0
    phishing_probability: float = 0.0
    class_probabilities: Dict[str, float] = {}

class NLPIndicator(BaseModel):
    category: str
    matched_phrases: List[str] = []
    severity: str = "LOW"

class NLPIndicators(BaseModel):
    score: float = 0.0
    indicators: List[NLPIndicator] = []
    detected_intent: List[str] = []

class URLFinding(BaseModel):
    url: str
    hostname: str = ""
    scheme: str = ""
    is_https: bool = False
    is_ip_address: bool = False
    is_shortened: bool = False
    brand_impersonation: List[str] = []
    typosquatting_detected: bool = False
    suspicious_keywords: List[str] = []
    risk_score: float = 0.0
    risk_level: str = "LOW"

class URLIntelligence(BaseModel):
    total_urls: int = 0
    suspicious_urls_count: int = 0
    extracted_urls: List[URLFinding] = []
    brand_impersonations: List[str] = []

class DomainIntelligence(BaseModel):
    domain: str = ""
    status: str = "available"  # available, unavailable, error
    mx_valid: Optional[bool] = None
    spf_record: Optional[Dict[str, Any]] = None
    dmarc_record: Optional[Dict[str, Any]] = None
    domain_age_days: Optional[int] = None
    risk_flags: List[str] = []

class AuthenticationResult(BaseModel):
    spf_result: str = "UNKNOWN"  # PASS, FAIL, NEUTRAL, NONE, UNKNOWN
    dkim_result: str = "UNKNOWN"
    dmarc_result: str = "UNKNOWN"
    from_reply_to_mismatch: bool = False
    from_return_path_mismatch: bool = False
    authentication_anomalies: List[str] = []

class RoutingForensics(BaseModel):
    origin_ip: Optional[str] = None
    hop_count: int = 0
    unusual_routing: bool = False
    routing_anomalies: List[str] = []
    origin_country: Optional[str] = None
    origin_provider: Optional[str] = None

class ThreatInfrastructure(BaseModel):
    ip: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    is_vpn_proxy: bool = False
    reputation_score: float = 0.0

class AIBriefing(BaseModel):
    executive_threat_assessment: str
    attack_vector_identified: str
    key_evidence: List[str]
    recommended_analyst_action: str
    confidence_note: str
    infrastructure_verdict: str

class ComprehensiveReport(BaseModel):
    evidence_seal: EvidenceSeal
    metadata: Metadata
    threat_score: ThreatScore
    ml_assessment: MLAssessment
    nlp_indicators: NLPIndicators
    url_intelligence: URLIntelligence
    routing_forensics: RoutingForensics
    authentication: AuthenticationResult
    domain_intelligence: DomainIntelligence
    threat_infrastructure: ThreatInfrastructure
    ai_investigative_briefing: AIBriefing

class AnalysisResponse(BaseModel):
    success: bool
    report: Optional[ComprehensiveReport] = None
    error: Optional[str] = None

class HealthCheckResponse(BaseModel):
    status: str
    version: str
    modules: Dict[str, str]
    timestamp: str
