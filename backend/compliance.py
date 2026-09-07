import re
import copy
from typing import Dict, Any, List


class IndiaPrivacyPreserver:
    """
    Privacy and PII protection layer for NETRA-Mail.

    The original forensic bytes are never modified.

    Sanitization is performed only on copies used for:
        - analyst display
        - API response
        - AI explanation
        - evidence summaries
    """

    PATTERNS = {

        # Payment cards:
        # 1234-5678-9012-3456
        # 1234 5678 9012 3456
        # 1234567890123456
        "CREDIT_CARD": re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
        ),

        # Indian PAN
        "INDIAN_PAN": re.compile(
            r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            re.IGNORECASE,
        ),

        # Indian mobile numbers
        "INDIAN_PHONE": re.compile(
            r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)"
        ),

        # Aadhaar-like 12 digit pattern
        "NATIONAL_ID_GENERIC": re.compile(
            r"\b\d{4}\s?\d{4}\s?\d{4}\b"
        ),

        # IFSC
        "IFSC_CODE": re.compile(
            r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
            re.IGNORECASE,
        ),

        # UPI-like identifier
        "UPI_ID": re.compile(
            r"\b[a-zA-Z0-9._-]{2,256}"
            r"@[a-zA-Z]{2,64}\b"
        ),

        # Email addresses
        "EMAIL": re.compile(
            r"\b[a-zA-Z0-9._%+\-]+"
            r"@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        ),

        # IPv4 addresses
        "IP_ADDRESS": re.compile(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ),

        # Long numeric account identifiers.
        "BANK_ACCOUNT": re.compile(
            r"(?<!\d)\d{9,18}(?!\d)"
        ),
    }

    @classmethod
    def _mask_card(
        cls,
        match: re.Match,
    ) -> str:
        """
        Preserve only the last four digits.
        """

        value = match.group(0)

        digits = re.sub(
            r"\D",
            "",
            value,
        )

        if len(digits) < 4:
            return "[REDACTED_PAYMENT_CARD]"

        return (
            "[REDACTED_PAYMENT_CARD:"
            f"****{digits[-4:]}]"
        )

    @classmethod
    def _mask_email(
        cls,
        match: re.Match,
    ) -> str:

        email = match.group(0)

        if "@" not in email:
            return "[REDACTED_EMAIL]"

        _, domain = email.split(
            "@",
            1,
        )

        # Preserve domain for threat-intelligence analysis.
        return f"***@{domain}"

    @classmethod
    def redact_text(
        cls,
        text: str,
    ) -> str:

        if not text:
            return ""

        redacted = str(text)

        # ---------------------------------------------------------
        # Most specific patterns first.
        # ---------------------------------------------------------

        redacted = cls.PATTERNS[
            "CREDIT_CARD"
        ].sub(
            cls._mask_card,
            redacted,
        )

        redacted = cls.PATTERNS[
            "NATIONAL_ID_GENERIC"
        ].sub(
            "[REDACTED_NATIONAL_ID]",
            redacted,
        )

        redacted = cls.PATTERNS[
            "INDIAN_PAN"
        ].sub(
            "[REDACTED_PAN]",
            redacted,
        )

        redacted = cls.PATTERNS[
            "IFSC_CODE"
        ].sub(
            "[REDACTED_IFSC]",
            redacted,
        )

        redacted = cls.PATTERNS[
            "INDIAN_PHONE"
        ].sub(
            "[REDACTED_PHONE]",
            redacted,
        )

        redacted = cls.PATTERNS[
            "UPI_ID"
        ].sub(
            "[REDACTED_UPI_ID]",
            redacted,
        )

        # Email addresses are masked after UPI so that
        # UPI identifiers are not accidentally transformed.
        redacted = cls.PATTERNS[
            "EMAIL"
        ].sub(
            cls._mask_email,
            redacted,
        )

        # Generic account numbers should be handled last.
        redacted = cls.PATTERNS[
            "BANK_ACCOUNT"
        ].sub(
            "[REDACTED_ACCOUNT_NUMBER]",
            redacted,
        )

        return redacted

    @classmethod
    def sanitize_payload(
        cls,
        parsed_email: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Deep-copy and sanitize an entire parsed email structure.

        The input dictionary is never modified.
        """

        clean = copy.deepcopy(
            parsed_email
        )

        # ---------------------------------------------------------
        # Body
        # ---------------------------------------------------------

        body = clean.get(
            "body",
            {},
        )

        clean["body"] = {
            "plain": cls.redact_text(
                body.get(
                    "plain",
                    "",
                )
            ),
            "html": cls.redact_text(
                body.get(
                    "html",
                    "",
                )
            ),
        }

        # ---------------------------------------------------------
        # Metadata
        # ---------------------------------------------------------

        metadata = clean.get(
            "metadata",
            {},
        )

        sanitized_metadata = {}

        for key, value in metadata.items():

            if key == "message_id":
                # Message IDs are useful for forensic correlation.
                sanitized_metadata[key] = value
                continue

            sanitized_metadata[key] = cls.redact_text(
                str(value)
            )

        clean["metadata"] = sanitized_metadata

        # ---------------------------------------------------------
        # Network chain
        # ---------------------------------------------------------

        # IP addresses are forensic indicators rather than PII
        # in this project, so retain them.
        clean["network_chain"] = clean.get(
            "network_chain",
            [],
        )

        # ---------------------------------------------------------
        # Attachments
        # ---------------------------------------------------------

        # Attachment hashes and metadata are safe to retain.
        clean["attachments"] = clean.get(
            "attachments",
            [],
        )

        return clean

    @classmethod
    def extract_redaction_findings(
        cls,
        text: str,
    ) -> List[Dict[str, Any]]:
        """
        Return metadata about what was redacted without returning
        the sensitive values themselves.
        """

        if not text:
            return []

        findings = []

        checks = [
            (
                "CREDIT_CARD",
                "Payment card number",
            ),
            (
                "INDIAN_PAN",
                "Indian PAN",
            ),
            (
                "INDIAN_PHONE",
                "Indian phone number",
            ),
            (
                "NATIONAL_ID_GENERIC",
                "National-ID-like number",
            ),
            (
                "IFSC_CODE",
                "IFSC code",
            ),
            (
                "UPI_ID",
                "UPI identifier",
            ),
            (
                "EMAIL",
                "Email address",
            ),
        ]

        for pattern_name, description in checks:

            matches = cls.PATTERNS[
                pattern_name
            ].findall(text)

            if matches:
                findings.append(
                    {
                        "type": pattern_name,
                        "description": description,
                        "count": len(matches),
                    }
                )

        return findings