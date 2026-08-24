from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import hashlib
import uvicorn
import traceback

from backend.parser import EmailIngestionEngine
from backend.header_analyzer import HeaderAnalyzer
from backend.domain_intel import DomainIntelEngine
from backend.geoip_mapper import GeoIPMapper
from backend.nlp_engine import NLPEngine
from backend.ml_classifier import LocalMLClassifier
from backend.compliance import ComplianceEngine
from backend.database import ThreatDatabase
from backend.llm_agent import LLMForensicAgent

app = FastAPI(
    title="Agentic MX - AI Threat Platform",
    description="Real-time email forensics, ML classification, and threat intelligence.",
    version="2.0.0"
)

# Enable CORS for browser extensions and external frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DirectEmailPayload(BaseModel):
    subject: str
    sender: str
    body: str
    headers_text: Optional[str] = ""

@app.on_event("startup")
def startup_event():
    ThreatDatabase.initialize()

@app.get("/")
def health_check():
    return {"status": "online", "message": "Agentic MX Engine is running."}

# ================= 1. FILE UPLOAD ENDPOINT (STREAMLIT / FORENSICS) =================
@app.post("/api/v1/analyze/file")
async def analyze_email_file(file: UploadFile = File(...)):
    """Ingests a raw .eml file and executes the complete multi-layer forensic pipeline."""
    try:
        raw_bytes = await file.read()
        
        # Ingestion & Cryptographic Hashing
        parsed_email = EmailIngestionEngine.parse_raw_email(raw_bytes)
        sender_email = parsed_email["metadata"]["from"]
        sender_domain = sender_email.split('@')[-1].strip('<>') if '@' in sender_email else "Unknown"
        
        # PII Scrubbing
        redacted_body = ComplianceEngine.mask_text(parsed_email["body"])
        
        # Header Forensics & Anomalies
        origin_ip = HeaderAnalyzer.extract_origin_ip(parsed_email["raw_header_text"])
        header_anomalies = HeaderAnalyzer.detect_timestamp_anomalies(parsed_email["raw_header_text"])
        
        # Infrastructure OSINT
        geo_intel = GeoIPMapper.get_ip_intel(origin_ip) if origin_ip else None
        domain_intel = DomainIntelEngine.inspect_domain(sender_domain)
        
        # ML & NLP Scans
        nlp_cues = NLPEngine.analyze_text(redacted_body)
        ml_prediction = LocalMLClassifier.predict(redacted_body)
        
        # Composite Threat Score (0-100)
        score = 0
        if ml_prediction["ml_classification"] == "Phishing":
            score += int(ml_prediction["confidence_score"] * 0.40)
        else:
            score += int((100 - ml_prediction["confidence_score"]) * 0.20)

        total_cues = sum(len(v) for v in nlp_cues.values())
        score += min(total_cues * 8, 25)

        if not domain_intel.get("has_valid_mx"):
            score += 10
        if domain_intel.get("is_newly_registered"):
            score += 10
        score += min(len(domain_intel.get("risk_flags", [])) * 3, 10)

        if geo_intel and geo_intel.get("is_cloud_vps"):
            score += 15

        final_threat_score = min(max(score, 0), 100)
        risk_level = "CRITICAL" if final_threat_score >= 80 else "HIGH" if final_threat_score >= 60 else "MEDIUM" if final_threat_score >= 40 else "LOW"

        # AI Synthesis
        ai_assessment = LLMForensicAgent.generate_assessment(
            metadata=parsed_email["metadata"],
            ml_assessment=ml_prediction,
            nlp_cues=nlp_cues,
            routing={"origin_ip": origin_ip, "anomalies": header_anomalies},
            infra={"geolocation": geo_intel, "domain_intelligence": domain_intel}
        )
        
        forensic_report = {
            "evidence_seal": parsed_email["evidence"],
            "metadata": parsed_email["metadata"],
            "threat_score": {
                "score": final_threat_score,
                "risk_level": risk_level
            },
            "ml_assessment": ml_prediction,
            "nlp_indicators": nlp_cues,
            "routing_forensics": {
                "origin_ip": origin_ip,
                "anomalies": header_anomalies
            },
            "threat_infrastructure": {
                "geolocation": geo_intel,
                "domain_intelligence": domain_intel
            },
            "ai_investigative_briefing": ai_assessment
        }
        
        ThreatDatabase.log_evidence(
            evidence_hash=parsed_email["evidence"]["sha256_hash"],
            ip=origin_ip,
            prediction=ml_prediction["ml_classification"],
            forensic_data=forensic_report
        )
        
        return JSONResponse(content={"success": True, "report": forensic_report})

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= 2. DIRECT WEBMAIL TEXT ENDPOINT (CHROME EXTENSION) =================
@app.post("/api/v1/analyze/text")
async def analyze_email_text(payload: DirectEmailPayload):
    """Zero-click direct analysis endpoint for real-time browser extension scans."""
    try:
        sender_domain = payload.sender.split('@')[-1].strip('<>') if '@' in payload.sender else "Unknown"
        
        # PII Scrubbing
        redacted_body = ComplianceEngine.mask_text(payload.body)
        
        # Optional Header Extraction
        origin_ip = HeaderAnalyzer.extract_origin_ip(payload.headers_text) if payload.headers_text else None
        header_anomalies = HeaderAnalyzer.detect_timestamp_anomalies(payload.headers_text) if payload.headers_text else []
        
        # OSINT & ML Assessment
        domain_intel = DomainIntelEngine.inspect_domain(sender_domain)
        geo_intel = GeoIPMapper.get_ip_intel(origin_ip) if origin_ip else None
        nlp_cues = NLPEngine.analyze_text(redacted_body)
        ml_prediction = LocalMLClassifier.predict(redacted_body)
        
        # Threat Scoring
        score = 0
        if ml_prediction["ml_classification"] == "Phishing":
            score += int(ml_prediction["confidence_score"] * 0.40)
        else:
            score += int((100 - ml_prediction["confidence_score"]) * 0.20)

        total_cues = sum(len(v) for v in nlp_cues.values())
        score += min(total_cues * 8, 25)

        if not domain_intel.get("has_valid_mx"):
            score += 10
        if domain_intel.get("is_newly_registered"):
            score += 10
        score += min(len(domain_intel.get("risk_flags", [])) * 3, 10)

        if geo_intel and geo_intel.get("is_cloud_vps"):
            score += 15

        final_threat_score = min(max(score, 0), 100)
        risk_level = "CRITICAL" if final_threat_score >= 80 else "HIGH" if final_threat_score >= 60 else "MEDIUM" if final_threat_score >= 40 else "LOW"

        # AI Synthesis
        ai_assessment = LLMForensicAgent.generate_assessment(
            metadata={"subject": payload.subject, "from": payload.sender},
            ml_assessment=ml_prediction,
            nlp_cues=nlp_cues,
            routing={"origin_ip": origin_ip, "anomalies": header_anomalies},
            infra={"geolocation": geo_intel, "domain_intelligence": domain_intel}
        )
        
        raw_content_repr = f"From: {payload.sender}\nSubject: {payload.subject}\n\n{payload.body}".encode()
        evidence_seal = {
            "sha256_hash": hashlib.sha256(raw_content_repr).hexdigest(),
            "byte_size": len(raw_content_repr)
        }

        forensic_report = {
            "evidence_seal": evidence_seal,
            "metadata": {"subject": payload.subject, "from": payload.sender},
            "threat_score": {
                "score": final_threat_score,
                "risk_level": risk_level
            },
            "ml_assessment": ml_prediction,
            "nlp_indicators": nlp_cues,
            "routing_forensics": {"origin_ip": origin_ip, "anomalies": header_anomalies},
            "threat_infrastructure": {"geolocation": geo_intel, "domain_intelligence": domain_intel},
            "ai_investigative_briefing": ai_assessment
        }
        
        ThreatDatabase.log_evidence(
            evidence_hash=evidence_seal["sha256_hash"],
            ip=origin_ip,
            prediction=ml_prediction["ml_classification"],
            forensic_data=forensic_report
        )
        
        return JSONResponse(content={"success": True, "report": forensic_report})

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
