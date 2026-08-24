import re

class ComplianceEngine:
    """Masks PII (Personally Identifiable Information) to comply with privacy laws."""
    
    # Regex patterns for common sensitive data
    PII_PATTERNS = {
        "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b',
        "PHONE_NUMBER": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "SSN_OR_GOV_ID": r'\b\d{3}-\d{2}-\d{4}\b'
    }

    @classmethod
    def mask_text(cls, text: str) -> str:
        """Scans text and replaces sensitive data with safe placeholder tags."""
        masked_text = text
        
        for pii_type, pattern in cls.PII_PATTERNS.items():
            # Replace the found pattern with a redacted tag like [CREDIT_CARD_REDACTED]
            masked_text = re.sub(pattern, f"[{pii_type}_REDACTED]", masked_text)
            
        # Special handling for emails: hide the username, keep the domain for threat hunting
        email_pattern = r'\b([A-Za-z0-9._%+-]+)(@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7})\b'
        masked_text = re.sub(email_pattern, r'***\2', masked_text)
        
        return masked_text
