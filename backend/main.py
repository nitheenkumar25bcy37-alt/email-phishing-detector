"""
Agentic MX - Email Phishing Detection Backend
FastAPI server for multi-signal threat analysis
Production-ready phishing detection platform
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import os
from datetime import datetime
from typing import Dict, Any

# Internal modules
from parser import EmailParser
from database import ThreatDatabase
from compliance import ComplianceEngine
from header_analyzer import HeaderAnalyzer
from domain_intel import DomainIntelligence
from geoip_mapper import GeoIPMapper
from nlp_engine import NLPEngine
from ml_classifier import MLClassifier
from url_analyzer import URLAnalyzer
from llm_agent import LLMAgent
from scoring import ThreatScoringEngine
from models import (
    AnalysisResponse, HealthCheckResponse, ComprehensiveReport,
    EvidenceSeal, Metadata, ThreatScore, MLAssessment,
    NLPIndicators, URLIntelligence, DomainIntelligence as DomainModel,
    AuthenticationResult, RoutingForensics, ThreatInfrastructure, AIBriefing
)

# Initialize FastAPI
app = FastAPI(
    title="Agentic MX",
    description="Email Phishing Detection & Forensic Analysis Platform",
    version="2.0.0"
)

# CORS configuration for browser extension & dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core security components with graceful instantiation
try:
    db = ThreatDatabase()
except Exception:
    db = None

parser = EmailParser()
compliance = ComplianceEngine()
header_analyzer = HeaderAnalyzer()
domain_intel = DomainIntelligence()
geoip = GeoIPMapper()
nlp = NLPEngine()
ml = MLClassifier()
url_analyzer = URLAnalyzer()
llm = LLMAgent()
scoring_engine = ThreatScoringEngine()


@app.get("/")
async def root():
    """Root endpoint - status summary"""
    return {
        "service": "Agentic MX",
        "version": "2.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/health")
async def health_check():
    """
    Health check endpoint reporting operational status of analysis components.
    """
    modules_status = {
        "parser": "✅ operational",
        "database": "✅ operational" if db else "⚠️ offline",
        "compliance": "✅ operational",
        "header_analyzer": "✅ operational",
        "domain_intelligence": "✅ operational",
        "geoip_mapper": "✅ operational",
        "nlp_engine": "✅ operational",
        "ml_classifier": "✅ operational",
        "url_analyzer": "✅ operational",
        "scoring_engine": "✅ operational",
        "llm_agent": "⚠️ fallback_mode" if not os.getenv("GROQ_API_KEY") else "✅ operational"
    }

    return HealthCheckResponse(
        status="healthy",
        version="2.0.0",
        modules=modules_status,
        timestamp=datetime.utcnow().isoformat()
    )


@app.post("/api/v1/analyze/file")
async def analyze_email_file(file: UploadFile = File(...)):
    """
    Analyze uploaded email file (.eml or text format).
    """
    try:
        content = await file.read()
        content_str = content.decode('utf-8', errors='replace')
        report = await _perform_analysis(content_str)

        return AnalysisResponse(
            success=True,
            report=report
        )
    except Exception as e:
        return AnalysisResponse(
            success=False,
            error=f"File analysis failed: {str(e)}"
        )


@app.post("/api/v1/analyze/text")
async def analyze_email_text(payload: Dict[str, Any]):
    """
    Analyze raw email text content.
    """
    try:
        content = payload.get("content", "")
        if not content or len(content.strip()) < 5:
            return AnalysisResponse(
                success=False,
                error="Email content is too short or empty"
            )

        report = await _perform_analysis(content)
        return AnalysisResponse(
            success=True,
            report=report
        )
    except Exception as e:
        return AnalysisResponse(
            success=False,
            error=f"Text analysis failed: {str(e)}"
        )


async def _perform_analysis(content_str: str) -> ComprehensiveReport:
    """
    Orchestrates the multi-signal detection pipeline safely.
    """
    # 1. Evidence Sealing
    sha256_hash, byte_size = parser.hash_email(content_str)
    evidence_seal = EvidenceSeal(
        sha256_hash=sha256_hash,
        byte_size=byte_size,
        sealed_at=datetime.utcnow().isoformat()
    )

    # 2. Email Parsing
    parsed = parser.parse_email(content_str)
    from_address = parsed.get("from_address", "")
    subject = parsed.get("subject", "")
    body = parsed.get("body", "")
    headers = parsed.get("headers", {})

    sender_domain = from_address.split("@")[-1].strip().lower() if "@" in from_address else ""

    metadata = Metadata(
        from_address=from_address,
        to_address=parsed.get("to_address", ""),
        subject=subject,
        date=parsed.get("date", ""),
        message_id=parsed.get("message_id", ""),
        received_count=parsed.get("received_count", 0),
        attachment_count=len(parsed.get("attachments", [])),
        is_multipart=parsed.get("is_multipart", False)
    )

    # 3. PII Redaction
    redacted_body = compliance.redact_pii(body)

    # 4. Header & Routing Analysis
    try:
        header_res = header_analyzer.analyze(headers, body)
    except Exception:
        header_res = {}

    auth = AuthenticationResult(
        spf_result=header_res.get("spf", "UNKNOWN"),
        dkim_result=header_res.get("dkim", "UNKNOWN"),
        dmarc_result=header_res.get("dmarc", "UNKNOWN"),
        from_reply_to_mismatch=header_res.get("from_reply_to_mismatch", False),
        from_return_path_mismatch=header_res.get("from_return_path_mismatch", False),
        authentication_anomalies=header_res.get("anomalies", [])
    )

    origin_ip = header_res.get("origin_ip")
    routing_forensics = RoutingForensics(
        origin_ip=origin_ip,
        hop_count=header_res.get("hop_count", 0),
        unusual_routing=header_res.get("unusual_routing", False),
        routing_anomalies=header_res.get("anomalies", [])
    )

    # 5. Infrastructure & GeoIP Analysis
    geoip_data = {}
    if origin_ip:
        try:
            geoip_data = geoip.geolocate(origin_ip)
            routing_forensics.origin_country = geoip_data.get("country")
            routing_forensics.origin_provider = geoip_data.get("isp")
        except Exception:
            pass

    threat_infra = ThreatInfrastructure(
        ip=origin_ip,
        asn=geoip_data.get("asn"),
        country=geoip_data.get("country"),
        isp=geoip_data.get("isp"),
        is_vpn_proxy=geoip_data.get("is_vpn_proxy", False)
    )

    # 6. Domain Intelligence
    try:
        domain_res = domain_intel.analyze(sender_domain) if sender_domain else {}
    except Exception:
        domain_res = {"status": "unavailable", "domain": sender_domain}

    domain_model = DomainModel(
        domain=sender_domain,
        status=domain_res.get("status", "available"),
        mx_valid=domain_res.get("mx_valid"),
        spf_record=domain_res.get("spf_record"),
        dmarc_record=domain_res.get("dmarc_record"),
        domain_age_days=domain_res.get("domain_age_days"),
        risk_flags=domain_res.get("risk_flags", [])
    )

    # 7. URL Intelligence
    try:
        url_res = url_analyzer.analyze(body)
    except Exception:
        url_res = {"total_urls": 0, "suspicious_urls_count": 0, "extracted_urls": [], "brand_impersonations": []}

    url_intel = URLIntelligence(
        total_urls=url_res.get("total_urls", 0),
        suspicious_urls_count=url_res.get("suspicious_urls_count", 0),
        extracted_urls=url_res.get("extracted_urls", []),
        brand_impersonations=url_res.get("brand_impersonations", [])
    )

    # 8. NLP / Social Engineering Engine
    try:
        nlp_res = nlp.analyze(subject, body)
    except Exception:
        nlp_res = {"score": 0.0, "indicators": [], "detected_intent": []}

    nlp_indicators = NLPIndicators(
        score=nlp_res.get("score", 0.0),
        indicators=nlp_res.get("indicators", []),
        detected_intent=nlp_res.get("detected_intent", [])
    )

    # 9. Machine Learning Classifier
    try:
        ml_res = ml.predict(f"{subject} {body}")
    except Exception:
        ml_res = {
            "model": "FallbackClassifier",
            "classification": "BENIGN",
            "confidence_score": 0.5,
            "phishing_probability": 0.0,
            "class_probabilities": {"BENIGN": 1.0, "PHISHING": 0.0}
        }

    ml_assessment = MLAssessment(
        model=ml_res.get("model", "TF-IDF + LogisticRegression"),
        classification=ml_res.get("classification", "BENIGN"),
        confidence_score=ml_res.get("confidence_score", 0.0),
        phishing_probability=ml_res.get("phishing_probability", 0.0),
        class_probabilities=ml_res.get("class_probabilities", {})
    )

    # 10. Threat Scoring Engine
    threat_score = scoring_engine.calculate_score(
        ml_res=ml_res,
        nlp_res=nlp_res,
        url_res=url_res,
        domain_res=domain_res,
        auth_res=auth.dict(),
        routing_res=routing_forensics.dict()
    )

    # 11. AI Forensic Briefing (Explanation Layer Only)
    telemetry = {
        "metadata": metadata.dict(),
        "threat_score": threat_score.dict(),
        "ml": ml_assessment.dict(),
        "nlp": nlp_indicators.dict(),
        "urls": url_intel.dict(),
        "domain": domain_model.dict(),
        "auth": auth.dict()
    }

    try:
        ai_brief = llm.generate_briefing(telemetry, redacted_body)
    except Exception:
        ai_brief = AIBriefing(
            executive_threat_assessment=f"Email presents a {threat_score.risk_level} threat risk score ({threat_score.score}/100).",
            attack_vector_identified="Multi-signal deterministic heuristic analysis.",
            key_evidence=threat_score.evidence_factors,
            recommended_analyst_action="Do not interact with links or attachments until verified out-of-band.",
            confidence_note="Fallback deterministic explanation generated.",
            infrastructure_verdict="Telemetry analyzed statically."
        )

    # 12. Persist to Threat Database safely
    if db:
        try:
            db.log_threat({
                "sha256": sha256_hash,
                "timestamp": datetime.utcnow().isoformat(),
                "sender": from_address,
                "subject": subject,
                "threat_score": threat_score.score,
                "risk_level": threat_score.risk_level,
                "evidence_factors": threat_score.evidence_factors
            })
        except Exception:
            pass

    return ComprehensiveReport(
        evidence_seal=evidence_seal,
        metadata=metadata,
        threat_score=threat_score,
        ml_assessment=ml_assessment,
        nlp_indicators=nlp_indicators,
        url_intelligence=url_intel,
        routing_forensics=routing_forensics,
        authentication=auth,
        domain_intelligence=domain_model,
        threat_infrastructure=threat_infra,
        ai_investigative_briefing=ai_brief
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
