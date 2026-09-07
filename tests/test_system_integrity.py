import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.compliance import ComplianceEngine

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_pii_redaction_credit_card():
    raw_text = "Please charge my Visa card 4532-0150-1234-5678 immediately."
    redacted = ComplianceEngine.mask_text(raw_text)
    assert "4532" not in redacted
    assert "[REDACTED_CC" in redacted

def test_phishing_scoring_logic():
    payload = {
        "subject": "URGENT: Verify Account Suspension",
        "sender": "security@paypal-verification-alert.com",
        "body": "Your account is suspended. Wire transfer the fee immediately to avoid penalty."
    }
    response = client.post("/api/v1/analyze/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["report"]["threat_score"]["score"] >= 60
    assert data["report"]["threat_score"]["risk_level"] in ["HIGH", "CRITICAL"]

def test_legitimate_scoring_logic():
    payload = {
        "subject": "Team Meeting Notes - Sprint Retrospective",
        "sender": "colleague@company.com",
        "body": "Here are the notes from our discussion earlier today. Let me know if anything is missing."
    }
    response = client.post("/api/v1/analyze/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["report"]["threat_score"]["score"] < 40
    assert data["report"]["threat_score"]["risk_level"] == "LOW"
