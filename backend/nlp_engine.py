import re
from typing import Dict, List

class NLPEngine:
    """Extracts social engineering, urgency, and BEC cues from email text."""
    
    URGENCY_PATTERNS = [
        r'\b(urgent|immediate(ly)? action|within 24 hours|suspended|terminated)\b',
        r'\b(final notice|overdue|failure to respond)\b'
    ]
    
    FINANCIAL_PATTERNS = [
        r'\b(wire transfer|swift|iban|routing number|crypto|bitcoin|usdt)\b',
        r'\b(unpaid invoice|payroll update|gift card)\b'
    ]
    
    CREDENTIAL_PATTERNS = [
        r'\b(verify( your)? (account|identity|credentials))\b',
        r'\b(reset( your)? password|login immediately)\b'
    ]

    @classmethod
    def analyze_text(cls, text: str) -> Dict[str, List[str]]:
        text_lower = text.lower()
        findings = {
            "urgency_cues": [],
            "financial_fraud_cues": [],
            "credential_harvesting_cues": []
        }

        # Scan for Urgency
        for pattern in cls.URGENCY_PATTERNS:
            matches = re.findall(pattern, text_lower)
            if matches:
                findings["urgency_cues"].extend([m if isinstance(m, str) else m[0] for m in matches])
                
        # Scan for Financial/BEC
        for pattern in cls.FINANCIAL_PATTERNS:
            matches = re.findall(pattern, text_lower)
            if matches:
                findings["financial_fraud_cues"].extend([m if isinstance(m, str) else m[0] for m in matches])

        # Scan for Credential Harvesting
        for pattern in cls.CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, text_lower)
            if matches:
                findings["credential_harvesting_cues"].extend([m if isinstance(m, str) else m[0] for m in matches])

        # Clean up duplicates
        return {k: list(set(v)) for k, v in findings.items()}
