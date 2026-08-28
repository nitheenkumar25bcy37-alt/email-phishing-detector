"""
Agentic MX — Email Phishing Detection Backend
FastAPI server for multi-signal threat analysis
Production-ready phishing detection platform
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import json
import os
from datetime import datetime
from typing import Optional, Dict, Any

# Internal modules
from parser import EmailParser
from database import ThreatDatabase
from compliance import ComplianceEngine
from header_analyzer import HeaderAnalyzer
from domain_intel import DomainIntelligence
from geoip_mapper import GeoIPMapper
from nlp_engine import NLPEngine
from ml_classifier import MLClassifier
from llm_agent import LLMAgent
from models import (
    AnalysisResponse, HealthCheckResponse, ThreatScore,
    MLAssessment, NLPIndicators, DomainIntelligence as DomainModel,
    AuthenticationResult, RoutingForensics, AIBriefing
)

# Initialize FastAPI
app = FastAPI(
    title="Agentic MX",
    description="Email Phishing Detection & Forensic Analysis Platform",
    version="2.0.0"
)

# CORS configuration for browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core components
db = ThreatDatabase()
parser = EmailParser()
compliance = ComplianceEngine()
header_analyzer = HeaderAnalyzer()
domain_intel = DomainIntelligence()
geoip = GeoIPMapper()
nlp = NLPEngine()
ml = MLClassifier()
llm = LLMAgent()

# Global state
ANALYSIS_CACHE = {}


@app.get("/")
async def root():
    """Root endpoint - health check"""
    return {
        "service": "Agentic MX",
        "version": "2.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/health")
async def health_check():
    """
    Health check endpoint with module status
    
    Returns:
        HealthCheckResponse with status of all components
    """
    modules_status = {
        "parser": "✅ operational",
        "database": "✅ operational" if db else "❌ failed",
        "compliance": "✅ operational",
        "header_analyzer": "✅ operational",
        "domain_intelligence": "✅ operational",
        "geoip_mapper": "✅ operational",
        "nlp_engine": "✅ operational",
        "ml_classifier": "✅ operational",
        "llm_agent": "⚠️ requires_api_key" if not os.getenv("GROQ_API_KEY") else "✅ operational"
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
    Analyze email file (.eml format)
    
    Args:
        file: Uploaded .eml email file
        
    Returns:
        Comprehensive threat analysis report
    """
    try:
        # Read file content
        content = await file.read()
        content_str = content.decode('utf-8', errors='replace')

        # Perform analysis
        report = await _perform_analysis(content_str, content)

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
async def analyze_email_text(payload: Dict[str, str]):
    """
    Analyze email content as raw text
    
    Args:
        payload: JSON with 'content' field containing email text
        
    Returns:
        Comprehensive threat analysis report
    """
    try:
        content = payload.get("content", "")

        if not content or len(content.strip()) < 10:
            raise ValueError("Email content too short")

        # Perform analysis
        report = await _perform_analysis(content, content.encode('utf-8'))

        return AnalysisResponse(
            success=True,
            report=report
        )

    except ValueError as ve:
        return AnalysisResponse(
            success=False,
            error=f"Invalid input: {str(ve)}"
        )
    except Exception as e:
        return AnalysisResponse(
            success=False,
            error=f"Text analysis failed: {str(e)}"
        )


async def _perform_analysis(content_str: str, content_bytes: bytes) -> Dict[str, Any]:
    """
    Perform comprehensive multi-signal threat analysis
    
    Args:
        content_str: Email content as string
        content_bytes: Email content as bytes
        
    Returns:
        Complete threat analysis report dictionary
    """

    # 1. EVIDENCE SEALING
    evidence_hash, byte_size = parser.hash_email(content_str)
    evidence_seal = {
        "sha256_hash": evidence_hash,
        "byte_size": byte_size,
        "sealed_at": datetime.utcnow().isoformat(),
        "encoding": "utf-8"
    }

    # 2. EMAIL PARSING
    parsed = parser.parse_email(content_str)
    if not parsed.get("success", True):
        return {
            "success": False,
            "error": "Email parsing failed",
            "evidence_seal": evidence_seal
        }

    # 3. EXTRACT KEY FIELDS
    from_address = parsed.get("from_address", "")
    subject = parsed.get("subject", "")
    body = parsed.get("body", "")
    sender_domain = from_address.split("@")[-1] if "@" in from_address else ""

    # 4. PII REDACTION
    redacted_body = compliance.redact_pii(body)

    # 5. METADATA
    metadata = {
        "from_address": from_address,
        "to_address": parsed.get("to_address", ""),
        "subject": subject,
        "date": parsed.get("date", ""),
        "message_id": parsed.get("message_id", ""),
        "received_count": parsed.get("received_count", 0),
        "attachment_count": len(parsed.get("attachments", [])),
        "is_multipart": parsed.get("is_multipart", False)
    }

    # 6. HEADER ANALYSIS
    headers = parsed.get("headers", {})
    routing_analysis = header_analyzer.analyze(headers, body)

    routing_forensics = {
        "origin_ip": routing_analysis.get("origin_ip"),
        "hop_count": routing_analysis.get("hop_count", 0),
        "unusual_routing": routing_analysis.get("unusual_routing", False),
        "routing_anomalies": routing_analysis.get("anomalies", [])
    }

    # 7. GEOIP ANALYSIS
    origin_ip = routing_analysis.get("origin_ip")
    geoip_data = {}
    if origin_ip:
        geoip_data = geoip.geolocate(origin_ip)
        routing_forensics["origin_country"] = geoip_data.get("country")
        routing_forensics["origin_provider"] = geoip_data.get("provider")

    # 8. DOMAIN INTELLIGENCE
    domain_analysis = domain_intel.analyze(sender_domain) if sender_domain else {}

    domain_intelligence = {
        "domain": sender_domain,
        "mx_valid": domain_analysis.get("mx_valid"),
        "spf_record": domain_analysis.get("spf_record"),
        "dmarc_record": domain_analysis.get("dmarc_record"),
        "domain_age_days": domain_analysis.get("domain_age_days"),
        "risk_flags": domain_analysis.get("risk_flags", [])
    }

    # 9. NLP ANALYSIS
    nlp_analysis = nlp.analyze(subject, body)
    nlp_indicators = {
        "indicators": [
            {
                "category": ind.get("category"),
                "matched_phrases": ind.get("phrases", []),
                "severity": ind.get("severity", "LOW")
            }
            for ind in nlp_analysis.get("indicators", [])
        ],
        "total_severity_score": nlp_analysis.get("severity_score", 0)
    }

    # 10. ML CLASSIFICATION
    ml_result = ml.classify(subject, body)
    ml_assessment = {
        "model": "tfidf_logistic_regression",
        "classification": ml_result.get("classification", "unknown"),
        "confidence_score": ml_result.get("confidence", 0),
        "phishing_probability": ml_result.get("phishing_probability", 0),
        "class_probabilities": ml_result.get("probabilities", {})
    }

    # 11. URL INTELLIGENCE (placeholder - BATCH 2)
    urls = parser.extract_urls(body)
    url_intelligence = {
        "urls_found": urls,
        "suspicious_urls": [],
        "risk_score": 0,
        "risk_level": "LOW"
    }

    # 12. AUTHENTICATION (placeholder - BATCH 2)
    authentication = {
        "spf_status": "UNKNOWN",
        "dkim_status": "UNKNOWN",
        "dmarc_status": "UNKNOWN",
        "authenticated": False,
        "anomalies": []
    }

    # 13. DETERMINISTIC THREAT SCORING
    threat_score = _calculate_threat_score(
        ml_assessment,
        nlp_indicators,
        url_intelligence,
        domain_intelligence,
        authentication,
        routing_forensics
    )

    # 14. AI FORENSIC BRIEFING
    ai_briefing = llm.investigate(
        subject=subject,
        body=redacted_body,
        ml_result=ml_assessment,
        nlp_result=nlp_indicators,
        urls=urls,
        domain_flags=domain_intelligence.get("risk_flags", []),
        threat_score=threat_score.get("total_score", 0)
    )

    # 15. BUILD REPORT
    report = {
        "evidence_seal": evidence_seal,
        "metadata": metadata,
        "threat_score": threat_score,
        "ml_assessment": ml_assessment,
        "nlp_indicators": nlp_indicators,
        "url_intelligence": url_intelligence,
        "routing_forensics": routing_forensics,
        "authentication": authentication,
        "domain_intelligence": domain_intelligence,
        "ai_investigative_briefing": ai_briefing,
        "attachments": parsed.get("attachments", [])
    }

    # 16. DATABASE LOGGING
    db.insert_threat_record({
        "evidence_hash": evidence_hash,
        "email_hash": evidence_hash,
        "threat_score": threat_score.get("total_score", 0),
        "risk_level": threat_score.get("risk_level", "UNKNOWN"),
        "classification": ml_assessment.get("classification"),
        "ml_confidence": ml_assessment.get("confidence_score", 0),
        "phishing_probability": ml_assessment.get("phishing_probability", 0),
        "sender_email": from_address,
        "sender_domain": sender_domain,
        "subject": subject,
        "origin_ip": routing_forensics.get("origin_ip"),
        "origin_country": routing_forensics.get("origin_country"),
        "url_risk_score": url_intelligence.get("risk_score", 0),
        "domain_risk_flags": domain_intelligence.get("risk_flags", []),
        "nlp_categories": [
            ind.get("category") for ind in nlp_indicators.get("indicators", [])
        ],
        "authentication_status": authentication.get("spf_status", "UNKNOWN"),
        "forensic_report": report,
        "byte_size": byte_size,
        "attachments_count": metadata.get("attachment_count", 0)
    })

    return report


def _calculate_threat_score(
    ml_result: Dict,
    nlp_result: Dict,
    url_result: Dict,
    domain_result: Dict,
    auth_result: Dict,
    routing_result: Dict
) -> Dict[str, Any]:
    """
    Calculate deterministic 0-100 threat score from multiple signals
    
    Scoring breakdown:
    - ML Classification: 0-30 points
    - NLP Social Engineering: 0-20 points
    - URL Intelligence: 0-20 points
    - Domain Intelligence: 0-15 points
    - Email Authentication: 0-10 points
    - Infrastructure/Routing: 0-5 points
    
    Total: 0-100 points
    """

    score = 0
    breakdown = {}
    signals = []

    # 1. ML CLASSIFICATION (max 30)
    ml_phishing_prob = ml_result.get("phishing_probability", 0)
    ml_score = int((ml_phishing_prob / 100) * 30)
    score += ml_score
    breakdown["ml"] = ml_score
    if ml_score > 15:
        signals.append(f"High ML phishing probability ({ml_phishing_prob:.0f}%)")

    # 2. NLP INDICATORS (max 20)
    nlp_indicators = nlp_result.get("indicators", [])
    nlp_score = 0
    has_urgency = False
    has_credential = False
    has_financial = False

    for indicator in nlp_indicators:
        if indicator.get("category") == "urgency":
            nlp_score += 8
            has_urgency = True
        elif indicator.get("category") == "credential_harvesting":
            nlp_score += 10
            has_credential = True
        elif indicator.get("category") == "financial_fraud":
            nlp_score += 8
            has_financial = True

    nlp_score = min(nlp_score, 20)
    score += nlp_score
    breakdown["nlp"] = nlp_score

    if has_urgency:
        signals.append("Urgency language detected")
    if has_credential:
        signals.append("Credential harvesting indicators")
    if has_financial:
        signals.append("Financial fraud language")

    # 3. URL INTELLIGENCE (max 20)
    url_score = url_result.get("risk_score", 0)
    url_score = min(url_score, 20)
    score += url_score
    breakdown["url"] = url_score
    if url_score > 10:
        signals.append(
            f"Suspicious URL detected (risk: {url_result.get('risk_level')})"
        )

    # 4. DOMAIN INTELLIGENCE (max 15)
    domain_risk_flags = domain_result.get("risk_flags", [])
    domain_score = 0

    if not domain_result.get("mx_valid"):
        domain_score += 5
    if not domain_result.get("spf_record"):
        domain_score += 3
    if not domain_result.get("dmarc_record"):
        domain_score += 2

    # Add points for each risk flag
    domain_score += min(len(domain_risk_flags) * 2, 5)

    domain_score = min(domain_score, 15)
    score += domain_score
    breakdown["domain"] = domain_score

    if len(domain_risk_flags) > 0:
        signals.append(f"Domain risk flags: {', '.join(domain_risk_flags[:2])}")

    # 5. EMAIL AUTHENTICATION (max 10)
    auth_score = 0
    spf_status = auth_result.get("spf_status", "UNKNOWN")
    dkim_status = auth_result.get("dkim_status", "UNKNOWN")
    dmarc_status = auth_result.get("dmarc_status", "UNKNOWN")

    if spf_status == "FAIL":
        auth_score += 4
    elif spf_status == "NEUTRAL":
        auth_score += 2

    if dkim_status == "FAIL":
        auth_score += 3
    if dmarc_status == "FAIL":
        auth_score += 3

    auth_score = min(auth_score, 10)
    score += auth_score
    breakdown["auth"] = auth_score

    if auth_score > 0:
        signals.append(f"Email authentication issues detected")

    # 6. INFRASTRUCTURE/ROUTING (max 5)
    routing_score = 0
    if routing_result.get("unusual_routing"):
        routing_score += 3
    if routing_result.get("origin_country") == "Unknown":
        routing_score += 2

    routing_score = min(routing_score, 5)
    score += routing_score
    breakdown["routing"] = routing_score

    # Final score and risk level
    final_score = min(max(score, 0), 100)

    if final_score <= 24:
        risk_level = "LOW"
    elif final_score <= 49:
        risk_level = "MEDIUM"
    elif final_score <= 74:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "total_score": final_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "primary_signals": signals[:3]  # Top 3 reasons
    }


@app.get("/api/v1/stats")
async def get_statistics():
    """Get threat analysis statistics"""
    try:
        stats = db.get_statistics()
        return {
            "success": True,
            "statistics": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/v1/recent")
async def get_recent_threats(limit: int = 20):
    """Get recent threat records"""
    try:
        threats = db.get_recent_threats(limit)
        return {
            "success": True,
            "threats": threats,
            "count": len(threats),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
