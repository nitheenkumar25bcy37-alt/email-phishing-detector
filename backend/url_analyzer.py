"""
Agentic MX - NLP & Social Engineering Engine
Detects social engineering triggers including urgency, credential harvesting,
financial fraud, impersonation, fear tactics, and Indian-specific scam context (UPI/KYC/Aadhaar/PAN).
"""

import re
from typing import Dict, Any, List

class NLPEngine:
    def __init__(self):
        self.categories = {
            "URGENT_ACTION": {
                "patterns": [r"urgent", r"immediately", r"action required", r"account suspended", r"final warning", r"last chance", r"verify pannunga", r"account block aagum"],
                "severity": "HIGH"
            },
            "CREDENTIAL_HARVESTING": {
                "patterns": [r"verify your account", r"verify your identity", r"confirm password", r"login", r"sign in", r"security verification", r"update credential"],
                "severity": "CRITICAL"
            },
            "FINANCIAL_FRAUD": {
                "patterns": [r"wire transfer", r"invoice payment", r"bank account", r"crypto deposit", r"upi payment", r"cashback reward", r"refund processed"],
                "severity": "HIGH"
            },
            "INDIAN_CONTEXT_SCAM": {
                "patterns": [r"aadhaar", r"pan card", r"kyc update", r"income tax refund", r"itr filing", r"epfo claim", r"sbi netbanking", r"otp share pannunga"],
                "severity": "HIGH"
            },
            "FEAR_AND_THREAT": {
                "patterns": [r"legal action", r"unauthorized activity", r"account termination", r"police report", r"penalty charge"],
                "severity": "MEDIUM"
            }
        }

    def analyze(self, subject: str, body: str) -> Dict[str, Any]:
        combined_text = f"{subject} {body}".lower()
        matched_indicators = []
        detected_intents = []
        total_nlp_score = 0.0

        for cat_name, cat_data in self.categories.items():
            matched_phrases = []
            for pattern in cat_data["patterns"]:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    matched_phrases.append(pattern.replace(r"\b", "").replace(r"\s+", " "))

            if matched_phrases:
                detected_intents.append(cat_name)
                sev = cat_data["severity"]
                score_weight = 6.0 if sev == "CRITICAL" else (4.0 if sev == "HIGH" else 2.0)
                total_nlp_score += score_weight

                matched_indicators.append({
                    "category": cat_name,
                    "matched_phrases": matched_phrases,
                    "severity": sev
                })

        return {
            "score": min(20.0, total_nlp_score),
            "indicators": matched_indicators,
            "detected_intent": detected_intents
        }
