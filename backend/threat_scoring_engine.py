"""
Agentic MX - Explainable Threat Scoring Engine

Deterministic 0-100 threat scoring.

Base component weights:
    ML                  30
    NLP                 20
    URL Intelligence    20
    Domain              15
    Authentication      10
    Infrastructure      5

Additional:
    Correlation / Evidence Escalation

The correlation layer prevents strong combinations of independent
signals from being underestimated by simple additive scoring.
"""

from typing import Dict, Any, List

from backend.models import (
    ScoreBreakdown,
    ThreatScore,
)


class ThreatScoringEngine:

    # ============================================================
    # MAXIMUM COMPONENT SCORES
    # ============================================================

    ML_MAX = 30.0
    NLP_MAX = 20.0
    URL_MAX = 20.0
    DOMAIN_MAX = 15.0
    AUTH_MAX = 10.0
    INFRA_MAX = 5.0

    # Maximum total
    TOTAL_MAX = 100

    # ============================================================
    # RISK LEVEL THRESHOLDS
    # ============================================================

    LOW_MAX = 24
    MEDIUM_MAX = 49
    HIGH_MAX = 74

    # ============================================================
    # MAIN SCORING FUNCTION
    # ============================================================

    def calculate_score(
        self,
        ml_res: Dict[str, Any],
        nlp_res: Dict[str, Any],
        url_res: Dict[str, Any],
        domain_res: Dict[str, Any],
        auth_res: Dict[str, Any],
        routing_res: Dict[str, Any],
    ) -> ThreatScore:

        evidence: List[str] = []

        # ========================================================
        # A. MACHINE LEARNING
        # ========================================================

        ml_probability = self._safe_float(
            ml_res.get(
                "phishing_probability",
                0.0
            )
        )

        ml_probability = max(
            0.0,
            min(
                1.0,
                ml_probability
            )
        )

        ml_score = (
            ml_probability *
            self.ML_MAX
        )

        if ml_probability >= 0.90:

            evidence.append(
                "ML classifier detected a very strong "
                f"phishing pattern "
                f"({ml_probability * 100:.1f}%)"
            )

        elif ml_probability >= 0.70:

            evidence.append(
                "ML classifier detected a strong "
                f"phishing pattern "
                f"({ml_probability * 100:.1f}%)"
            )

        elif ml_probability >= 0.55:

            evidence.append(
                "ML classifier detected a suspicious "
                f"phishing pattern "
                f"({ml_probability * 100:.1f}%)"
            )

        # ========================================================
        # B. NLP / SOCIAL ENGINEERING
        # ========================================================

        nlp_score = self._safe_float(
            nlp_res.get(
                "score",
                0.0
            )
        )

        nlp_score = max(
            0.0,
            min(
                self.NLP_MAX,
                nlp_score
            )
        )

        indicators = nlp_res.get(
            "indicators",
            []
        )

        if not isinstance(
            indicators,
            list
        ):
            indicators = []

        for indicator in indicators:

            if not isinstance(
                indicator,
                dict
            ):
                continue

            category = indicator.get(
                "category"
            )

            severity = indicator.get(
                "severity",
                "LOW"
            )

            if category:

                evidence.append(
                    f"NLP trigger: {category}"
                    f" ({severity})"
                )

        # ========================================================
        # C. URL INTELLIGENCE
        # ========================================================

        url_score = 0.0

        suspicious_count = self._safe_int(
            url_res.get(
                "suspicious_urls_count",
                0
            )
        )

        brands = url_res.get(
            "brand_impersonations",
            []
        )

        if not isinstance(
            brands,
            list
        ):
            brands = []

        # --------------------------------------------------------
        # Brand impersonation
        # --------------------------------------------------------

        if brands:

            url_score += 10.0

            evidence.append(
                "URL brand impersonation detected: "
                + ", ".join(
                    str(x)
                    for x in brands
                )
            )

        # --------------------------------------------------------
        # Suspicious URLs
        # --------------------------------------------------------

        if suspicious_count > 0:

            points = min(
                6.0,
                suspicious_count * 3.0
            )

            url_score += points

            evidence.append(
                f"{suspicious_count} suspicious "
                "URL(s) detected by URL intelligence"
            )

        # --------------------------------------------------------
        # URL-specific indicators
        # --------------------------------------------------------

        findings = url_res.get(
            "extracted_urls",
            []
        )

        if not isinstance(
            findings,
            list
        ):
            findings = []

        indicator_points = 0.0

        seen_keywords = set()

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            keywords = finding.get(
                "suspicious_keywords",
                []
            )

            if not isinstance(
                keywords,
                list
            ):
                continue

            for keyword in keywords:

                keyword = str(
                    keyword
                ).lower()

                if keyword in seen_keywords:
                    continue

                seen_keywords.add(
                    keyword
                )

                if keyword == "userinfo_auth_trick":

                    indicator_points += 4.0

                    evidence.append(
                        "URL contains a userinfo "
                        "authentication trick"
                    )

                elif keyword == "raw_ip_hostname":

                    indicator_points += 3.0

                    evidence.append(
                        "URL uses a raw IP address "
                        "as the hostname"
                    )

                elif keyword == "url_shortener":

                    indicator_points += 2.0

                    evidence.append(
                        "URL uses a known URL shortener"
                    )

                elif keyword == "deep_subdomains":

                    indicator_points += 2.0

                    evidence.append(
                        "URL contains unusually deep "
                        "subdomain nesting"
                    )

                elif keyword == "typosquatting":

                    indicator_points += 3.0

                    evidence.append(
                        "URL shows possible "
                        "typosquatting"
                    )

        url_score += min(
            4.0,
            indicator_points
        )

        # --------------------------------------------------------
        # Use URL engine's own risk score as additional evidence
        # --------------------------------------------------------

        extracted = findings

        highest_url_risk = 0.0

        for finding in extracted:

            if not isinstance(
                finding,
                dict
            ):
                continue

            risk = self._safe_float(
                finding.get(
                    "risk_score",
                    0.0
                )
            )

            highest_url_risk = max(
                highest_url_risk,
                risk
            )

        # Do not double-count the entire URL risk score.
        # Only use it to strengthen the URL component when the
        # URL engine reports severe risk.

        if highest_url_risk >= 80:

            url_score = max(
                url_score,
                16.0
            )

            evidence.append(
                "URL intelligence reports a "
                f"severe URL risk score "
                f"({highest_url_risk:.0f}/100)"
            )

        elif highest_url_risk >= 60:

            url_score = max(
                url_score,
                13.0
            )

        elif highest_url_risk >= 40:

            url_score = max(
                url_score,
                10.0
            )

        url_score = min(
            self.URL_MAX,
            url_score
        )

        # ========================================================
        # D. DOMAIN INTELLIGENCE
        # ========================================================

        domain_score = 0.0

        mx_valid = domain_res.get(
            "mx_valid"
        )

        if mx_valid is False:

            domain_score += 6.0

            evidence.append(
                "Sender domain has no valid MX record"
            )

        status = str(
            domain_res.get(
                "status",
                "unknown"
            )
        ).lower()

        if status == "available":

            age = domain_res.get(
                "domain_age_days"
            )

            if age is not None:

                age = self._safe_float(
                    age
                )

                if age < 30:

                    domain_score += 5.0

                    evidence.append(
                        "Newly registered domain "
                        f"({int(age)} days old)"
                    )

                elif age < 90:

                    domain_score += 3.0

                    evidence.append(
                        "Recently registered domain "
                        f"({int(age)} days old)"
                    )

        flags = domain_res.get(
            "risk_flags",
            []
        )

        if not isinstance(
            flags,
            list
        ):
            flags = []

        for flag in flags:

            if domain_score >= self.DOMAIN_MAX:
                break

            domain_score += 2.0

            evidence.append(
                f"Domain risk flag: {flag}"
            )

        domain_score = min(
            self.DOMAIN_MAX,
            domain_score
        )

        # ========================================================
        # E. EMAIL AUTHENTICATION
        # ========================================================

        auth_score = 0.0

        spf = str(
            auth_res.get(
                "spf_result",
                "UNKNOWN"
            )
        ).upper()

        dmarc = str(
            auth_res.get(
                "dmarc_result",
                "UNKNOWN"
            )
        ).upper()

        if spf == "FAIL":

            auth_score += 3.0

            evidence.append(
                "SPF authentication failed"
            )

        if dmarc == "FAIL":

            auth_score += 3.0

            evidence.append(
                "DMARC authentication failed"
            )

        if auth_res.get(
            "from_reply_to_mismatch",
            False
        ):

            auth_score += 4.0

            evidence.append(
                "From address does not match Reply-To"
            )

        if auth_res.get(
            "from_return_path_mismatch",
            False
        ):

            auth_score += 2.0

            evidence.append(
                "From address does not match "
                "Return-Path"
            )

        auth_score = min(
            self.AUTH_MAX,
            auth_score
        )

        # ========================================================
        # F. INFRASTRUCTURE / ROUTING
        # ========================================================

        infra_score = 0.0

        if routing_res.get(
            "unusual_routing",
            False
        ):

            infra_score += 3.0

            evidence.append(
                "Unusual mail routing detected"
            )

        anomalies = routing_res.get(
            "routing_anomalies",
            []
        )

        if not isinstance(
            anomalies,
            list
        ):
            anomalies = []

        if anomalies:

            infra_score += 2.0

            evidence.append(
                f"{len(anomalies)} routing "
                "anomaly/anomalies detected"
            )

        infra_score = min(
            self.INFRA_MAX,
            infra_score
        )

        # ========================================================
        # BASE SCORE
        # ========================================================

        base_score = (
            ml_score
            + nlp_score
            + url_score
            + domain_score
            + auth_score
            + infra_score
        )

        # ========================================================
        # CORRELATED EVIDENCE ESCALATION
        # ========================================================
        #
        # This is the important improvement.
        #
        # A phishing attack often produces several related
        # indicators. Treating every indicator independently can
        # underestimate the real-world threat.
        #
        # We therefore apply bounded escalation only when strong
        # combinations are present.
        #
        # The final score remains capped at 100.
        # ========================================================

        escalation = 0.0

        # --------------------------------------------------------
        # ML + brand impersonation
        # --------------------------------------------------------

        strong_ml = (
            ml_probability >= 0.90
        )

        has_brand = bool(
            brands
        )

        if strong_ml and has_brand:

            escalation += 25.0

            evidence.append(
                "Critical correlation: high-confidence "
                "ML detection combined with brand impersonation"
            )

        # --------------------------------------------------------
        # ML + severe URL intelligence
        # --------------------------------------------------------

        if (
            ml_probability >= 0.90
            and highest_url_risk >= 70
        ):

            escalation += 15.0

            evidence.append(
                "Critical correlation: ML phishing detection "
                "confirmed by severe URL intelligence"
            )

        # --------------------------------------------------------
        # Brand + suspicious authentication language
        # --------------------------------------------------------

        phishing_action_keywords = {
            "login",
            "verify",
            "account",
            "security",
            "secure",
            "password",
            "update",
            "confirm",
            "signin",
        }

        matched_action_keywords = set()

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            keywords = finding.get(
                "suspicious_keywords",
                []
            )

            if not isinstance(
                keywords,
                list
            ):
                continue

            for keyword in keywords:

                keyword = str(
                    keyword
                ).lower()

                if keyword in phishing_action_keywords:

                    matched_action_keywords.add(
                        keyword
                    )

        if (
            has_brand
            and len(matched_action_keywords) >= 2
        ):

            escalation += 10.0

            evidence.append(
                "Strong phishing correlation: brand "
                "impersonation combined with multiple "
                "credential/action keywords"
            )

        # --------------------------------------------------------
        # Multiple independent components
        # --------------------------------------------------------

        active_components = 0

        if ml_score > 0:
            active_components += 1

        if nlp_score > 0:
            active_components += 1

        if url_score > 0:
            active_components += 1

        if domain_score > 0:
            active_components += 1

        if auth_score > 0:
            active_components += 1

        if infra_score > 0:
            active_components += 1

        if active_components >= 4:

            escalation += 5.0

            evidence.append(
                "Multiple independent threat intelligence "
                "components contributed to the assessment"
            )

        # --------------------------------------------------------
        # Bound escalation
        # --------------------------------------------------------

        escalation = min(
            escalation,
            40.0
        )

        # ========================================================
        # FINAL SCORE
        # ========================================================

        total = (
            base_score
            + escalation
        )

        total = int(
            round(total)
        )

        total = max(
            0,
            min(
                self.TOTAL_MAX,
                total
            )
        )

        # ========================================================
        # RISK LEVEL
        # ========================================================

        if total <= self.LOW_MAX:

            risk_level = "LOW"

        elif total <= self.MEDIUM_MAX:

            risk_level = "MEDIUM"

        elif total <= self.HIGH_MAX:

            risk_level = "HIGH"

        else:

            risk_level = "CRITICAL"

        # ========================================================
        # SPECIAL CRITICAL OVERRIDE
        # ========================================================
        #
        # This protects against a mathematically low score when
        # there is overwhelming evidence.
        #
        # It does NOT change the numeric score.
        # ========================================================

        if (
            ml_probability >= 0.95
            and has_brand
            and highest_url_risk >= 70
        ):

            if risk_level != "CRITICAL":

                risk_level = "CRITICAL"

            evidence.append(
                "Critical threat verdict: overwhelming "
                "multi-signal phishing evidence detected"
            )

        # ========================================================
        # BREAKDOWN
        # ========================================================

        breakdown = ScoreBreakdown(

            ml_score=round(
                ml_score,
                1
            ),

            nlp_score=round(
                nlp_score,
                1
            ),

            url_score=round(
                url_score,
                1
            ),

            domain_score=round(
                domain_score,
                1
            ),

            auth_score=round(
                auth_score,
                1
            ),

            infra_score=round(
                infra_score,
                1
            ),
        )

        # ========================================================
        # REMOVE DUPLICATE EVIDENCE
        # ========================================================

        evidence = list(
            dict.fromkeys(
                evidence
            )
        )

        # ========================================================
        # RETURN
        # ========================================================

        return ThreatScore(

            score=total,

            risk_level=risk_level,

            breakdown=breakdown,

            evidence_factors=evidence,

        )

    # ============================================================
    # COMPATIBILITY ALIAS
    # ============================================================

    def calculate(
        self,
        *args,
        **kwargs
    ) -> ThreatScore:

        return self.calculate_score(
            *args,
            **kwargs
        )

    # ============================================================
    # SAFE FLOAT
    # ============================================================

    @staticmethod
    def _safe_float(
        value: Any
    ) -> float:

        try:

            return float(
                value
            )

        except (
            TypeError,
            ValueError
        ):

            return 0.0

    # ============================================================
    # SAFE INTEGER
    # ============================================================

    @staticmethod
    def _safe_int(
        value: Any
    ) -> int:

        try:

            return int(
                value
            )

        except (
            TypeError,
            ValueError
        ):

            return 0