import re
from typing import Dict, List, Any


class NLPEngine:
    """
    NETRA-MAIL NLP Engine

    Detects common phishing/social-engineering language using
    explainable lexical indicators.

    Categories:
        - urgency
        - credential_harvesting
        - financial_fraud
        - social_engineering

    The engine returns a normalized 0-100 content risk score.
    """

    # ---------------------------------------------------------
    # Indicator dictionaries
    # ---------------------------------------------------------

    CATEGORIES = {

        "urgency": [
            "urgent",
            "immediately",
            "within 24 hours",
            "final notice",
            "suspended",
            "terminated",
            "act now",
            "last warning",
            "expires today",
            "account suspended",
            "account will be suspended",

            "locked",
            "locked account",
            "locked out",
            "action required",
            "critical",
            "urgent action",
            "urgent verification",
            "verify now",
            "confirm now",
            "do it today",
            "expires",
            "expired",
            "time sensitive",
            "time-sensitive",
            "asap",
            "as soon as possible",
            "without delay",
            "don't delay",
            "do not delay",
            "immediate",
            "pressing",
            "emergency",
            "alert",
            "warning",
            "must complete",
            "failure to",
            "must act",
            "will be disabled",
            "will be suspended",
            "will be locked",
            "cannot access",
            "blocks account",
            "block account",
            "respond immediately",
            "respond now",
            "take action",
            "immediate attention",
            "attention required",
            "action needed",
        ],

        "credential_harvesting": [
            "verify your account",
            "verify account",
            "confirm your identity",
            "reset password",
            "login",
            "log in",
            "sign in",
            "authenticate",
            "unlock account",
            "verify identity",
            "security verification",
            "confirm password",
            "enter your password",
            "update your password",

            "re-authenticate",
            "re-enter",
            "validate account",
            "validate identity",
            "confirm account",
            "confirm login",
            "re-login",
            "reconfirm",
            "secure access",
            "secure login",
            "security check",
            "security code",
            "verification code",
            "enter pin",
            "enter code",
            "two-factor",
            "two factor",
            "2fa",
            "enter your details",
            "provide your details",
            "confirm details",
            "personal information",
            "sensitive information",
            "private information",
            "account information",
            "banking information",
            "credit card information",
            "card number",
            "card details",
            "password",
            "username",
            "user name",
            "credentials",
            "credential",
            "verification",
            "authentication",
            "security credentials",
            "account credentials",
            "security information",
        ],

        "financial_fraud": [
            "wire transfer",
            "bank transfer",
            "invoice",
            "payment",
            "gift card",
            "crypto",
            "bitcoin",
            "usdt",
            "swift",
            "iban",
            "vendor bank",
            "payroll",
            "beneficiary",
            "bank account",

            "transfer funds",
            "urgent transfer",
            "immediate transfer",
            "wire funds",
            "transfer money",
            "account holder",
            "routing number",
            "account number",
            "bank details",
            "banking details",
            "financial",
            "funds",
            "money",
            "payment request",
            "invoice payment",
            "purchase",
            "purchase gift cards",
            "google play",
            "itunes",
            "amazon gift",
            "paypal",
            "stripe",
            "square cash",
            "venmo",
            "transaction",
            "transactions",
            "balance",
            "deposit",
            "withdrawal",
            "currency",
            "deal",
            "acquisition",
            "acquisition deal",
            "business deal",
            "partner bank",
            "new partner",

            "send money",
            "send funds",
            "make a payment",
            "payment immediately",
            "payment today",
            "bank transfer request",
            "financial transaction",
            "payment details",
            "banking details",
            "gift cards",
            "gift card",
            "purchase cards",
        ],

        "social_engineering": [
            "keep this confidential",
            "do not tell",
            "do not share",
            "secret",
            "ceo",
            "director",
            "manager",
            "click here",
            "failure to comply",
            "immediate action",

            "confidential",
            "highly confidential",
            "do not notify",
            "don't notify",
            "do not inform",
            "don't inform",
            "do not discuss",
            "don't discuss",
            "don't tell anyone",
            "tell no one",
            "do not forward",
            "don't forward",
            "private matter",
            "sensitive matter",
            "confidential matter",
            "executive",
            "c-level",
            "authority",
            "executive order",
            "trusted",
            "trust",
            "trustworthy",
            "vip",
            "vip customer",
            "special request",
            "special favor",
            "on behalf",
            "behalf of",
            "requested",
            "request",
            "demands",
            "demand",
            "must complete",
            "must finish",
            "must send",
            "must transfer",
            "must process",
            "require",
            "requires",
            "required",
            "must cooperate",
            "cooperation needed",
            "your cooperation",
            "this will damage",
            "damage",
            "damages",

            "do not contact",
            "do not call",
            "do not question",
            "keep private",
            "keep secret",
            "urgent request",
            "special instruction",
            "special instructions",
            "personal request",
            "executive request",
            "director request",
            "ceo request",
            "boss",
            "supervisor",
            "authority figure",
            "confidential request",
            "private request",
        ],
    }

    # ---------------------------------------------------------
    # Category weights
    # ---------------------------------------------------------

    CATEGORY_WEIGHTS = {
        "urgency": 8,
        "financial_fraud": 15,
        "credential_harvesting": 18,
        "social_engineering": 12,
    }

    # Maximum contribution from each category.
    CATEGORY_CAPS = {
        "urgency": 28,
        "financial_fraud": 45,
        "credential_harvesting": 45,
        "social_engineering": 36,
    }

    # ---------------------------------------------------------
    # Utility
    # ---------------------------------------------------------

    @staticmethod
    def _normalize_text(text: str) -> str:
        text = str(text or "")
        text = text.lower()

        # Normalize common whitespace variations.
        text = re.sub(r"\s+", " ", text)

        return text.strip()

    @staticmethod
    def _contains_term(text: str, term: str) -> bool:
        """
        Match phrases without accidentally matching a word
        inside another word.
        """

        pattern = rf"(?<!\w){re.escape(term.lower())}(?!\w)"

        return re.search(pattern, text) is not None

    # ---------------------------------------------------------
    # Main analysis
    # ---------------------------------------------------------

    @classmethod
    def analyze_text(cls, text: str) -> Dict[str, Any]:

        text = cls._normalize_text(text)

        findings: Dict[str, List[str]] = {}

        # -----------------------------------------------------
        # Detect indicators
        # -----------------------------------------------------

        for category, terms in cls.CATEGORIES.items():

            matches = []

            for term in terms:

                if cls._contains_term(text, term):
                    matches.append(term)

            if matches:
                findings[category] = sorted(set(matches))

        # -----------------------------------------------------
        # Calculate base category score
        # -----------------------------------------------------

        score = 0

        category_scores = {}

        for category, matches in findings.items():

            weight = cls.CATEGORY_WEIGHTS.get(
                category,
                5,
            )

            cap = cls.CATEGORY_CAPS.get(
                category,
                30,
            )

            category_score = min(
                cap,
                weight * len(matches),
            )

            category_scores[category] = category_score

            score += category_score

        # -----------------------------------------------------
        # Independent category correlation
        # -----------------------------------------------------

        active_categories = len(findings)

        # Two categories = meaningful evidence.
        if active_categories >= 2:
            score += 12

        # Three categories = strong evidence.
        if active_categories >= 3:
            score += 12

        # All four = very strong social-engineering pattern.
        if active_categories >= 4:
            score += 10

        # -----------------------------------------------------
        # High-value combinations
        # -----------------------------------------------------

        urgency = bool(
            findings.get("urgency")
        )

        financial = bool(
            findings.get("financial_fraud")
        )

        credential = bool(
            findings.get("credential_harvesting")
        )

        social = bool(
            findings.get("social_engineering")
        )

        # Urgency + credential harvesting is a classic
        # account takeover pattern.
        if urgency and credential:
            score += 12

        # Urgency + financial request is a strong BEC pattern.
        if urgency and financial:
            score += 14

        # Financial + credential harvesting indicates
        # possible financial account theft.
        if financial and credential:
            score += 14

        # Social engineering + financial request is
        # particularly relevant to CEO/BEC fraud.
        if social and financial:
            score += 16

        # Social engineering + urgency is also strong.
        if social and urgency:
            score += 12

        # Social engineering + credential request.
        if social and credential:
            score += 12

        # CEO/executive language combined with a financial
        # request is a strong BEC indicator.
        executive_terms = {
            "ceo",
            "director",
            "manager",
            "executive",
            "c-level",
            "boss",
            "supervisor",
        }

        executive_present = any(
            term in findings.get(
                "social_engineering",
                [],
            )
            for term in executive_terms
        )

        if executive_present and financial:
            score += 18

        # -----------------------------------------------------
        # Special high-confidence patterns
        # -----------------------------------------------------

        # Account takeover pattern.
        if (
            credential
            and urgency
            and (
                "password" in text
                or "login" in text
                or "sign in" in text
                or "account" in text
            )
        ):
            score += 10

        # Payment/transfer request under urgency.
        if (
            financial
            and urgency
            and (
                "transfer" in text
                or "payment" in text
                or "invoice" in text
                or "funds" in text
            )
        ):
            score += 10

        # -----------------------------------------------------
        # Final score
        # -----------------------------------------------------

        score = min(
            100,
            max(
                0,
                int(round(score)),
            ),
        )

        # -----------------------------------------------------
        # Attack classification
        # -----------------------------------------------------

        attack_types = []

        if credential:
            attack_types.append(
                "Credential Phishing"
            )

        if financial:
            attack_types.append(
                "Financial Fraud / BEC"
            )

        if social:
            attack_types.append(
                "Social Engineering"
            )

        if (
            urgency
            and not attack_types
        ):
            attack_types.append(
                "Social Engineering"
            )

        # -----------------------------------------------------
        # Risk level
        # -----------------------------------------------------

        if score >= 75:
            risk_level = "CRITICAL"

        elif score >= 50:
            risk_level = "HIGH"

        elif score >= 25:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        # -----------------------------------------------------
        # Matched indicator count
        # -----------------------------------------------------

        matched_count = sum(
            len(values)
            for values in findings.values()
        )

        # -----------------------------------------------------
        # Return
        # -----------------------------------------------------

        return {
            "score": score,

            "categories": {
                "urgency": findings.get(
                    "urgency",
                    [],
                ),

                "financial_fraud": findings.get(
                    "financial_fraud",
                    [],
                ),

                "credential_harvesting": findings.get(
                    "credential_harvesting",
                    [],
                ),

                "social_engineering": findings.get(
                    "social_engineering",
                    [],
                ),
            },

            "category_scores": category_scores,

            "matched_indicator_count": matched_count,

            "attack_classification": attack_types,

            "risk_level": risk_level,
        }