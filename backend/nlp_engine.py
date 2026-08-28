# FILE: backend/nlp_engine.py
"""
Agentic MX — NLP / Social Engineering Analysis Engine
Detects categorized linguistic indicators of social engineering,
including India-specific (UPI/Aadhaar/PAN/GST/EPFO, Romanized
regional-language) scam phrasing. Phrase-list based, no external NLP
model dependency required.
"""

import re
from typing import Dict, Any, List, Tuple

CATEGORY_PHRASES: Dict[str, List[str]] = {
    "urgency": [
        "urgent", "immediately", "action required", "account suspended",
        "final warning", "last chance", "act now", "expires today",
        "within 24 hours", "time sensitive", "respond immediately",
    ],
    "credential_harvesting": [
        "verify your account", "verify your identity", "confirm password",
        "sign in", "login now", "security verification", "re-enter your password",
        "update your credentials", "confirm your details", "validate your account",
    ],
    "financial_fraud": [
        "wire transfer", "payment", "invoice", "bank account", "gift card",
        "crypto", "transfer funds", "cryptocurrency", "bitcoin payment",
        "processing fee", "release your funds",
    ],
    "impersonation": [
        "it department", "administrator", "system administrator", "ceo",
        "human resources", "hr department", "bank support", "payment provider",
        "customer support team", "help desk",
    ],
    "fear_threat": [
        "account will be closed", "legal action", "suspension", "unauthorized activity",
        "your account has been locked", "permanently disabled", "penalty",
        "will be terminated", "police complaint",
    ],
    "indian_context": [
        "upi", "ifsc", "otp", "aadhaar", "pan card", "gst", "epfo",
        "income tax", "itr", "kyc", "kyc update", "courier held",
        "parcel held at customs", "cashback", "refund pending",
        "loan approved", "credit card blocked", "qr code payment",
        "verify pannunga", "account block aagum", "otp share pannunga",
        "kyc update pannunga", "kyc panna", "block agum",
    ],
}

CATEGORY_WEIGHTS: Dict[str, int] = {
    "urgency": 8,
    "credential_harvesting": 10,
    "financial_fraud": 8,
    "impersonation": 5,
    "fear_threat": 7,
    "indian_context": 4,
}


def _phrase_pattern(phrase: str) -> re.Pattern:
    escaped = re.escape(phrase.lower())
    return re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")


_COMPILED_PATTERNS: Dict[str, List[Tuple[str, re.Pattern]]] = {
    category: [(phrase, _phrase_pattern(phrase)) for phrase in phrases]
    for category, phrases in CATEGORY_PHRASES.items()
}


def _severity_for_count(count: int) -> str:
    if count >= 3:
        return "HIGH"
    if count == 2:
        return "MEDIUM"
    return "LOW"


class NLPEngine:
    """Categorized social-engineering phrase detection."""

    def analyze(self, subject: str, body: str) -> Dict[str, Any]:
        text = f"{subject or ''} \n {body or ''}".lower()

        indicators: List[Dict[str, Any]] = []
        severity_score = 0

        try:
            for category, patterns in _COMPILED_PATTERNS.items():
                matched_phrases = []
                for phrase, pattern in patterns:
                    if pattern.search(text):
                        matched_phrases.append(phrase)

                if not matched_phrases:
                    continue

                severity = _severity_for_count(len(matched_phrases))
                weight = CATEGORY_WEIGHTS.get(category, 5)
                severity_score += weight * min(len(matched_phrases), 3)

                indicators.append({
                    "category": category,
                    "phrases": matched_phrases,
                    "severity": severity,
                })
        except Exception:
            pass

        return {
            "indicators": indicators,
            "severity_score": min(severity_score, 100),
        }
