from typing import Dict, Any, List


class DecisionEngine:

    """
    Converts threat intelligence into an operational decision.

    Risk bands:

        0-24    SAFE
        25-49   LOW
        50-74   HIGH
        75-100  CRITICAL

    Additional correlation rules prevent multiple independent
    phishing signals from being hidden by weighted averaging.
    """

    THRESHOLDS = {
        "SAFE_MAX": 24,
        "LOW_MAX": 49,
        "HIGH_MAX": 74,
    }

    @classmethod
    def _normalize_score(
        cls,
        score: Any,
    ) -> int:

        try:
            return max(
                0,
                min(
                    100,
                    int(
                        round(
                            float(score)
                        )
                    ),
                ),
            )

        except Exception:
            return 0

    @classmethod
    def _risk_from_score(
        cls,
        score: int,
    ) -> str:

        if score <= 24:
            return "SAFE"

        if score <= 49:
            return "LOW"

        if score <= 74:
            return "HIGH"

        return "CRITICAL"

    @classmethod
    def _action_from_risk(
        cls,
        risk: str,
    ) -> str:

        return {
            "SAFE": "ALLOW",
            "LOW": "REVIEW",
            "HIGH": "QUARANTINE",
            "CRITICAL": "BLOCK",
        }.get(
            risk,
            "REVIEW",
        )

    @staticmethod
    def _unique(
        values: List[str],
    ) -> List[str]:

        return list(
            dict.fromkeys(
                value
                for value in values
                if value
            )
        )

    @classmethod
    def decide(
        cls,
        scoring: Dict[str, Any],
        nlp_analysis: Dict[str, Any] = None,
        ml_analysis: Dict[str, Any] = None,
        domain_analysis: Dict[str, Any] = None,
        url_analysis: Dict[str, Any] = None,
        header_analysis: Dict[str, Any] = None,
        infrastructure: Dict[str, Any] = None,
    ) -> Dict[str, Any]:

        scoring = scoring or {}

        score = cls._normalize_score(
            scoring.get(
                "threat_score",
                scoring.get(
                    "score",
                    0,
                ),
            )
        )

        confidence = cls._normalize_score(
            scoring.get(
                "confidence",
                0,
            )
        )

        reasons = []
        attack_types = []

        # =========================================================
        # NLP
        # =========================================================

        nlp = nlp_analysis or {}

        categories = nlp.get(
            "categories",
            {},
        )

        urgency = categories.get(
            "urgency",
            [],
        )

        financial = categories.get(
            "financial_fraud",
            [],
        )

        credentials = categories.get(
            "credential_harvesting",
            [],
        )

        social = categories.get(
            "social_engineering",
            [],
        )

        nlp_score = cls._normalize_score(
            nlp.get(
                "score",
                0,
            )
        )

        if urgency:

            reasons.append(
                "Urgency indicators detected: "
                + ", ".join(
                    sorted(set(urgency))[:5]
                )
            )

        if financial:

            reasons.append(
                "Financial-fraud indicators detected: "
                + ", ".join(
                    sorted(set(financial))[:5]
                )
            )

            attack_types.append(
                "Financial Fraud / BEC"
            )

        if credentials:

            reasons.append(
                "Credential-harvesting indicators detected: "
                + ", ".join(
                    sorted(set(credentials))[:5]
                )
            )

            attack_types.append(
                "Credential Phishing"
            )

        if social:

            reasons.append(
                "Social-engineering indicators detected: "
                + ", ".join(
                    sorted(set(social))[:5]
                )
            )

            attack_types.append(
                "Social Engineering"
            )

        # =========================================================
        # ML
        # =========================================================

        ml = ml_analysis or {}

        classification = str(
            ml.get(
                "classification",
                "",
            )
        ).upper()

        probability = ml.get(
            "phishing_probability",
            0,
        )

        if classification == "PHISHING":

            reasons.append(
                "Machine-learning classifier identified phishing."
            )

            attack_types.append(
                "Phishing"
            )

        if (
            isinstance(
                probability,
                (int, float),
            )
            and probability >= 0.50
        ):

            reasons.append(
                "ML phishing probability is "
                f"{probability * 100:.1f}%."
            )

        # =========================================================
        # DOMAIN
        # =========================================================

        domain = domain_analysis or {}

        brands = domain.get(
            "impersonated_brands",
            [],
        )

        domain_score = cls._normalize_score(
            domain.get(
                "highest_risk_score",
                0,
            )
        )

        if brands:

            reasons.append(
                "Sender/domain impersonation detected: "
                + ", ".join(
                    sorted(set(brands))
                )
            )

            attack_types.append(
                "Brand Impersonation"
            )

        for reason in domain.get(
            "reasons",
            [],
        )[:5]:

            reasons.append(
                reason
            )

        # =========================================================
        # URL
        # =========================================================

        url = url_analysis or {}

        url_summary = url.get(
            "summary",
            {},
        )

        url_score = cls._normalize_score(
            url_summary.get(
                "highest_url_score",
                0,
            )
        )

        url_brands = url_summary.get(
            "impersonated_brands",
            [],
        )

        if url_brands:

            reasons.append(
                "Suspicious URL brand impersonation: "
                + ", ".join(
                    sorted(set(url_brands))
                )
            )

            attack_types.append(
                "Malicious URL"
            )

        # =========================================================
        # AUTHENTICATION
        # =========================================================

        header = header_analysis or {}

        auth = header.get(
            "authentication",
            {},
        )

        spf = str(
            auth.get(
                "spf",
                "none",
            )
        ).upper()

        dkim = str(
            auth.get(
                "dkim",
                "none",
            )
        ).upper()

        dmarc = str(
            auth.get(
                "dmarc",
                "none",
            )
        ).upper()

        auth_failures = 0

        if spf == "FAIL":

            auth_failures += 1

            reasons.append(
                "SPF validation failed."
            )

        elif spf == "NONE":

            reasons.append(
                "SPF authentication result is unavailable."
            )

        if dkim == "FAIL":

            auth_failures += 1

            reasons.append(
                "DKIM validation failed."
            )

        elif dkim == "NONE":

            reasons.append(
                "DKIM authentication result is unavailable."
            )

        if dmarc == "FAIL":

            auth_failures += 1

            reasons.append(
                "DMARC validation/alignment failed."
            )

        elif dmarc == "NONE":

            reasons.append(
                "DMARC authentication result is unavailable."
            )

        # =========================================================
        # INFRASTRUCTURE
        # =========================================================

        infra = infrastructure or {}

        if infra.get(
            "is_cloud_vps",
            False,
        ):

            reasons.append(
                "Origin infrastructure is associated with "
                "cloud/VPS hosting."
            )

        if infra.get("ip"):

            reasons.append(
                "Originating IP identified: "
                f"{infra.get('ip')}."
            )

        # =========================================================
        # CORRELATION ENGINE
        # =========================================================

        correlation_findings = []

        phishing_signals = 0

        if classification == "PHISHING":
            phishing_signals += 1

        if brands:
            phishing_signals += 1

        if domain_score >= 30:
            phishing_signals += 1

        if nlp_score >= 30:
            phishing_signals += 1

        if urgency and financial:
            phishing_signals += 1

        if credentials:
            phishing_signals += 1

        if url_score >= 30:
            phishing_signals += 1

        if auth_failures >= 1:
            phishing_signals += 1

        # ---------------------------------------------------------
        # Rule 1:
        # ML phishing + brand impersonation
        # ---------------------------------------------------------

        if (
            classification == "PHISHING"
            and brands
        ):

            score = max(
                score,
                60,
            )

            correlation_findings.append(
                "Phishing classifier and brand impersonation agree."
            )

        # ---------------------------------------------------------
        # Rule 2:
        # Brand impersonation + suspicious domain
        # ---------------------------------------------------------

        if (
            brands
            and domain_score >= 30
        ):

            score = max(
                score,
                55,
            )

            correlation_findings.append(
                "Brand impersonation combined with suspicious domain intelligence."
            )

        # ---------------------------------------------------------
        # Rule 3:
        # Urgency + financial fraud
        # ---------------------------------------------------------

        if (
            urgency
            and financial
        ):

            score = max(
                score,
                55,
            )

            correlation_findings.append(
                "Urgency and financial-fraud indicators correlate."
            )

        # ---------------------------------------------------------
        # Rule 4:
        # ML + NLP + domain
        # ---------------------------------------------------------

        independent_major_signals = sum(
            [
                classification == "PHISHING",
                bool(
                    brands
                ),
                nlp_score >= 30,
                url_score >= 50,
            ]
        )

        if independent_major_signals >= 3:

            score = max(
                score,
                70,
            )

            correlation_findings.append(
                "Multiple independent phishing signals agree."
            )

        # ---------------------------------------------------------
        # Rule 5:
        # Authentication weakness adds confidence
        # ---------------------------------------------------------

        if (
            brands
            and auth_failures >= 1
        ):

            score = max(
                score,
                65,
            )

            correlation_findings.append(
                "Brand impersonation is accompanied by authentication failure."
            )

        # ---------------------------------------------------------
        # Rule 6:
        # Three or more independent signals
        # ---------------------------------------------------------

        if phishing_signals >= 4:

            score = max(
                score,
                70,
            )

            correlation_findings.append(
                "Four or more independent threat signals detected."
            )

        # =========================================================
        # FINAL RISK
        # =========================================================

        score = cls._normalize_score(
            score
        )

        risk = cls._risk_from_score(
            score
        )

        action = cls._action_from_risk(
            risk
        )

        # =========================================================
        # FALLBACK
        # =========================================================

        if not reasons:

            reasons.append(
                "No significant phishing indicators were identified."
            )

        reasons.extend(
            correlation_findings
        )

        reasons = cls._unique(
            reasons
        )

        attack_types = cls._unique(
            attack_types
        )

        return {
            "risk": risk,
            "score": score,
            "action": action,
            "confidence": confidence,
            "reasons": reasons,
            "attack_classification": attack_types,
        }

    @classmethod
    def evaluate(
        cls,
        scoring: Dict[str, Any],
        **kwargs,
    ) -> Dict[str, Any]:

        return cls.decide(
            scoring,
            **kwargs,
        )