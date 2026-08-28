"""
Agentic MX - Compliance & Privacy Engine
Redacts Sensitive Personally Identifiable Information (PII) before sending payload to external APIs.
"""

import re

class ComplianceEngine:
    def __init__(self):
        # Compiled Regular Expressions for efficient PII scrubbing
        self.email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE)
        self.phone_regex = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
        self.pan_regex = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b')
        self.aadhaar_regex = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
        self.upi_regex = re.compile(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}')
        self.key_value_pass = re.compile(r'(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*(\S+)', re.IGNORECASE)

    def redact_pii(self, text: str) -> str:
        """
        Redacts standard PII and Indian-specific financial identifiers from email text.
        """
        if not text:
            return ""

        redacted = text

        # 1. Mask PASSWORDS & SECRETS
        redacted = self.key_value_pass.sub(r'\1: [REDACTED_SECRET]', redacted)

        # 2. Mask INDIAN SENSITIVE IDENTIFIERS
        redacted = self.pan_regex.sub('[PAN_REDACTED]', redacted)
        redacted = self.aadhaar_regex.sub('[AADHAAR_REDACTED]', redacted)

        # 3. Mask PHONE NUMBERS
        redacted = self.phone_regex.sub('[PHONE_REDACTED]', redacted)

        # 4. Mask EMAIL ADDRESSES (optional safety mask for body text)
        # Retain domain context where useful, but anonymize user portion
        def mask_email(match):
            full_email = match.group(0)
            parts = full_email.split('@')
            return f"user_redacted@{parts[1]}"

        redacted = self.email_regex.sub(mask_email, redacted)

        return redacted
