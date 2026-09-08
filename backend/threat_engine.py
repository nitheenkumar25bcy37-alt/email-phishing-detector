from typing import Dict, Any


class ThreatScoringEngine:
    """
    NETRA-MAIL multi-signal threat scoring engine.

    Combines:

        ML
        NLP
        Domain Intelligence
        URL Intelligence
        Authentication
        Infrastructure

    Final score:
        0-24   SAFE
        25-49  LOW
        50-74  HIGH
        75-100 CRITICAL
    """

    # ---------------------------------------------------------
    # Weights
    # ---------------------------------------------------------

    WEIGHTS = {
        "ml": 0.25,
        "nlp": 0.25,
        "domain": 0.25,
        "url": 0.10,
        "authentication": 0.10,
        "infrastructure": 0.05,
        "attachments": 0.10,
    }

    # ---------------------------------------------------------
    # Utility
    # ---------------------------------------------------------

    @staticmethod
    def _clamp(value: float) -> int:
        return int(
            max(
                0,
                min(
                    100,
                    round(value),
                ),
            )
        )

    # ---------------------------------------------------------
    # NLP
    # ---------------------------------------------------------

    @staticmethod
    def _nlp_score_from_result(
        nlp_result: Dict[str, Any],
    ) -> int:

        if not nlp_result:
            return 0

        # If the NLP engine already calculated a score,
        # preserve it.
        upstream_score = nlp_result.get(
            "score"
        )

        if isinstance(
            upstream_score,
            (int, float),
        ):
            return ThreatScoringEngine._clamp(
                upstream_score
            )

        categories = nlp_result.get(
            "categories",
            {},
        )

        if not isinstance(
            categories,
            dict,
        ):
            return 0

        urgency = categories.get(
            "urgency",
            [],
        ) or []

        financial = categories.get(
            "financial_fraud",
            [],
        ) or []

        credential = categories.get(
            "credential_harvesting",
            [],
        ) or []

        social = categories.get(
            "social_engineering",
            [],
        ) or []

        urgency_count = len(
            set(urgency)
        )

        financial_count = len(
            set(financial)
        )

        credential_count = len(
            set(credential)
        )

        social_count = len(
            set(social)
        )

        score = 0

        # -----------------------------------------------------
        # Category contributions
        # -----------------------------------------------------

        score += min(
            28,
            urgency_count * 8,
        )

        score += min(
            45,
            financial_count * 15,
        )

        score += min(
            45,
            credential_count * 18,
        )

        score += min(
            36,
            social_count * 12,
        )

        # -----------------------------------------------------
        # Independent category count
        # -----------------------------------------------------

        active_categories = sum(
            [
                urgency_count > 0,
                financial_count > 0,
                credential_count > 0,
                social_count > 0,
            ]
        )

        if active_categories >= 2:
            score += 12

        if active_categories >= 3:
            score += 12

        if active_categories >= 4:
            score += 10

        # -----------------------------------------------------
        # High-value combinations
        # -----------------------------------------------------

        urgency_present = (
            urgency_count > 0
        )

        financial_present = (
            financial_count > 0
        )

        credential_present = (
            credential_count > 0
        )

        social_present = (
            social_count > 0
        )

        # Account takeover pattern.
        if (
            urgency_present
            and credential_present
        ):
            score += 12

        # Urgent payment / transfer.
        if (
            urgency_present
            and financial_present
        ):
            score += 14

        # Financial + credential theft.
        if (
            financial_present
            and credential_present
        ):
            score += 14

        # Social engineering + financial fraud.
        if (
            social_present
            and financial_present
        ):
            score += 16

        # Social engineering + urgency.
        if (
            social_present
            and urgency_present
        ):
            score += 12

        # Social engineering + credential harvesting.
        if (
            social_present
            and credential_present
        ):
            score += 12

        # -----------------------------------------------------
        # Executive/BEC pattern
        # -----------------------------------------------------

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
            term in social
            for term in executive_terms
        )

        if (
            executive_present
            and financial_present
        ):
            score += 18

        return ThreatScoringEngine._clamp(
            score
        )

    # ---------------------------------------------------------
    # ML
    # ---------------------------------------------------------

    @staticmethod
    def _ml_score_from_result(
        ml_result: Dict[str, Any],
    ) -> int:

        if not ml_result:
            return 0

        probability = ml_result.get(
            "phishing_probability"
        )

        if isinstance(
            probability,
            (int, float),
        ):
            return ThreatScoringEngine._clamp(
                float(probability) * 100
            )

        confidence = ml_result.get(
            "confidence_score"
        )

        classification = str(
            ml_result.get(
                "ml_classification",
                ml_result.get(
                    "classification",
                    "",
                ),
            )
        ).lower()

        if isinstance(
            confidence,
            (int, float),
        ):

            if (
                "phish" in classification
                or classification in {
                    "malicious",
                    "suspicious",
                }
            ):
                return ThreatScoringEngine._clamp(
                    confidence
                )

            return ThreatScoringEngine._clamp(
                100 - confidence
            )

        return 0

    # ---------------------------------------------------------
    # Domain
    # ---------------------------------------------------------

    @staticmethod
    def _domain_score(
        domain_result: Dict[str, Any],
    ) -> int:

        if not domain_result:
            return 0

        possible_scores = [
            domain_result.get(
                "highest_risk_score",
                0,
            ),
            domain_result.get(
                "risk_score",
                0,
            ),
            domain_result.get(
                "score",
                0,
            ),
        ]

        numeric_scores = [
            value
            for value in possible_scores
            if isinstance(
                value,
                (int, float),
            )
        ]

        return ThreatScoringEngine._clamp(
            max(
                numeric_scores,
                default=0,
            )
        )

    # ---------------------------------------------------------
    # URL
    # ---------------------------------------------------------

    @staticmethod
    def _url_score(
        url_result: Any,
    ) -> int:

        if not url_result:
            return 0

        if isinstance(
            url_result,
            dict,
        ):

            summary = url_result.get(
                "summary",
                {},
            )

            if isinstance(
                summary,
                dict,
            ):

                summary_score = summary.get(
                    "highest_url_score",
                    summary.get(
                        "highest_risk_score",
                        summary.get(
                            "risk_score",
                            0,
                        ),
                    ),
                )

                if isinstance(
                    summary_score,
                    (int, float),
                ):
                    return ThreatScoringEngine._clamp(
                        summary_score
                    )

            urls = url_result.get(
                "urls",
                [],
            )

        else:
            urls = url_result

        scores = []

        for item in urls or []:

            if not isinstance(
                item,
                dict,
            ):
                continue

            analysis = item.get(
                "analysis",
                item,
            )

            if not isinstance(
                analysis,
                dict,
            ):
                continue

            score = analysis.get(
                "risk_score",
                item.get(
                    "risk_score",
                    0,
                ),
            )

            if isinstance(
                score,
                (int, float),
            ):
                scores.append(
                    score
                )

        return ThreatScoringEngine._clamp(
            max(
                scores,
                default=0,
            )
        )

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    @staticmethod
    def _authentication_score(
        header_result: Dict[str, Any],
    ) -> int:

        if not header_result:
            return 0

        possible_scores = [
            header_result.get(
                "header_risk_score",
                0,
            ),
            header_result.get(
                "risk_score",
                0,
            ),
            header_result.get(
                "score",
                0,
            ),
        ]

        numeric_scores = [
            value
            for value in possible_scores
            if isinstance(
                value,
                (int, float),
            )
        ]

        return ThreatScoringEngine._clamp(
            max(
                numeric_scores,
                default=0,
            )
        )

    # ---------------------------------------------------------
    # Infrastructure
    # ---------------------------------------------------------

    @staticmethod
    def _infrastructure_score(
        infrastructure: Dict[str, Any],
    ) -> int:

        if not infrastructure:
            return 0

        score = 0

        if infrastructure.get(
            "is_cloud_vps",
            False,
        ):
            score += 45

        isp = str(
            infrastructure.get(
                "isp",
                "",
            )
        ).lower()

        organization = str(
            infrastructure.get(
                "organization",
                "",
            )
        ).lower()

        asn = str(
            infrastructure.get(
                "asn",
                "",
            )
        ).lower()

        combined = (
            f"{isp} "
            f"{organization} "
            f"{asn}"
        )

        hosting_keywords = [
            "digitalocean",
            "amazon",
            "aws",
            "linode",
            "ovh",
            "hetzner",
            "choopa",
            "vultr",
            "m247",
            "hostinger",
            "contabo",
            "hosting",
            "vps",
            "datacenter",
            "data center",
        ]

        if any(
            keyword in combined
            for keyword in hosting_keywords
        ):
            score += 30

        # IP presence alone is weak evidence.
        if infrastructure.get(
            "ip"
        ):
            score += 5

        return ThreatScoringEngine._clamp(
            score
        )

    # ---------------------------------------------------------
    # Main evaluation
    # ---------------------------------------------------------

    @classmethod
    def evaluate(
        cls,
        header_res: Dict[str, Any],
        url_res: Any,
        nlp_res: Any = None,
        ml_res: Any = None,
        domain_res: Dict[str, Any] = None,
        infrastructure: Dict[str, Any] = None,
        attachment_res: Dict[str, Any] = None,
    ) -> Dict[str, Any]:

        # -----------------------------------------------------
        # Normalize NLP
        # -----------------------------------------------------

        if isinstance(
            nlp_res,
            (int, float),
        ):

            nlp_score = cls._clamp(
                float(nlp_res) * 100
                if float(nlp_res) <= 1
                else float(nlp_res)
            )

        else:

            nlp_score = (
                cls._nlp_score_from_result(
                    nlp_res or {}
                )
            )

        # -----------------------------------------------------
        # Normalize ML
        # -----------------------------------------------------

        if isinstance(
            ml_res,
            (int, float),
        ):

            ml_score = cls._clamp(
                float(ml_res) * 100
                if float(ml_res) <= 1
                else float(ml_res)
            )

        else:

            ml_score = (
                cls._ml_score_from_result(
                    ml_res or {}
                )
            )

        # -----------------------------------------------------
        # Individual signals
        # -----------------------------------------------------

        authentication_score = (
            cls._authentication_score(
                header_res or {}
            )
        )

        url_score = cls._url_score(
            url_res
        )

        domain_score = cls._domain_score(
            domain_res or {}
        )

        infrastructure_score = (
            cls._infrastructure_score(
                infrastructure or {}
            )
        )

        attachment_score = cls._clamp(
            (attachment_res or {}).get("score", 0)
        )

        # -----------------------------------------------------
        # Weighted base score
        # -----------------------------------------------------

        base_score = (

            ml_score
            * cls.WEIGHTS["ml"]

            + nlp_score
            * cls.WEIGHTS["nlp"]

            + domain_score
            * cls.WEIGHTS["domain"]

            + url_score
            * cls.WEIGHTS["url"]

            + authentication_score
            * cls.WEIGHTS["authentication"]

            + infrastructure_score
            * cls.WEIGHTS["infrastructure"]
            + attachment_score
            * cls.WEIGHTS["attachments"]
        )

        # -----------------------------------------------------
        # Correlation bonuses
        # -----------------------------------------------------

        bonuses = []

        bonus_score = 0

        brands = set(
            (domain_res or {}).get(
                "impersonated_brands",
                [],
            )
            or []
        )

        # -----------------------------------------------------
        # Brand impersonation
        # -----------------------------------------------------

        if brands:

            bonus_score += 12

            bonuses.append(
                "Brand impersonation detected."
            )

        if (
            brands
            and nlp_score >= 20
        ):

            bonus_score += 15

            bonuses.append(
                "Brand impersonation combined with "
                "social-engineering language."
            )

        if (
            brands
            and authentication_score >= 10
        ):

            bonus_score += 10

            bonuses.append(
                "Brand impersonation combined with "
                "authentication concerns."
            )

        # -----------------------------------------------------
        # ML + NLP
        # -----------------------------------------------------

        if (
            ml_score >= 50
            and nlp_score >= 20
        ):

            bonus_score += 15

            bonuses.append(
                "ML and NLP independently indicate phishing."
            )

        # -----------------------------------------------------
        # ML + domain
        # -----------------------------------------------------

        if (
            ml_score >= 55
            and domain_score >= 50
        ):

            bonus_score += 10

            bonuses.append(
                "ML phishing signal agrees with "
                "suspicious domain intelligence."
            )

        # -----------------------------------------------------
        # NLP + domain
        # -----------------------------------------------------

        if (
            nlp_score >= 40
            and domain_score >= 40
        ):

            bonus_score += 12

            bonuses.append(
                "Social-engineering content agrees "
                "with domain risk."
            )

        # -----------------------------------------------------
        # Infrastructure + domain
        # -----------------------------------------------------

        if (
            infrastructure_score >= 40
            and domain_score >= 50
        ):

            bonus_score += 5

            bonuses.append(
                "Suspicious infrastructure agrees "
                "with domain risk."
            )

        # -----------------------------------------------------
        # NLP categories
        # -----------------------------------------------------

        nlp_categories = {}

        if isinstance(
            nlp_res,
            dict,
        ):

            nlp_categories = (
                nlp_res.get(
                    "categories",
                    {},
                )
                or {}
            )

        financial_present = bool(
            nlp_categories.get(
                "financial_fraud",
                [],
            )
        )

        credential_present = bool(
            nlp_categories.get(
                "credential_harvesting",
                [],
            )
        )

        urgency_present = bool(
            nlp_categories.get(
                "urgency",
                [],
            )
        )

        social_present = bool(
            nlp_categories.get(
                "social_engineering",
                [],
            )
        )

        # -----------------------------------------------------
        # Financial + domain
        # -----------------------------------------------------

        if (
            financial_present
            and domain_score >= 40
        ):

            bonus_score += 12

            bonuses.append(
                "Financial-fraud language combined "
                "with a suspicious sender domain."
            )

        # -----------------------------------------------------
        # Credential + domain
        # -----------------------------------------------------

        if (
            credential_present
            and domain_score >= 50
        ):

            bonus_score += 8

            bonuses.append(
                "Credential-harvesting language combined "
                "with a suspicious sender domain."
            )

        # -----------------------------------------------------
        # Urgency + financial
        # -----------------------------------------------------

        if (
            urgency_present
            and financial_present
        ):

            bonus_score += 8

            bonuses.append(
                "Urgency and financial-fraud signals "
                "occur together."
            )

        # -----------------------------------------------------
        # Social engineering + financial
        # -----------------------------------------------------

        if (
            social_present
            and financial_present
        ):

            bonus_score += 10

            bonuses.append(
                "Social-engineering language combined "
                "with financial activity."
            )

        # -----------------------------------------------------
        # Social engineering + urgency
        # -----------------------------------------------------

        if (
            social_present
            and urgency_present
        ):

            bonus_score += 8

            bonuses.append(
                "Social-engineering language combined "
                "with urgency."
            )

        # -----------------------------------------------------
        # CEO/BEC pattern
        # -----------------------------------------------------

        executive_terms = {
            "ceo",
            "director",
            "manager",
            "executive",
            "c-level",
            "boss",
            "supervisor",
        }

        social_terms = set(
            nlp_categories.get(
                "social_engineering",
                [],
            )
            or []
        )

        executive_present = bool(
            executive_terms
            & social_terms
        )

        if (
            executive_present
            and financial_present
        ):

            bonus_score += 15

            bonuses.append(
                "Executive impersonation combined "
                "with financial activity."
            )

        suspicious_attachments = int(
            (attachment_res or {}).get("suspicious_attachment_count", 0) or 0
        )

        if suspicious_attachments:
            bonuses.append(
                f"{suspicious_attachments} suspicious attachment(s) detected."
            )

        if attachment_score >= 50 and (
            nlp_score >= 25 or domain_score >= 30 or url_score >= 30
        ):
            bonus_score += 15
            bonuses.append(
                "Suspicious attachment corroborates independent phishing evidence."
            )

        # -----------------------------------------------------
        # Safety floor
        # -----------------------------------------------------

        active_strong_signals = sum(
            [
                ml_score >= 50,
                nlp_score >= 30,
                domain_score >= 40,
                url_score >= 50,
                authentication_score >= 20,
                infrastructure_score >= 30,
                attachment_score >= 35,
                bool(
                    (header_res or {}).get("alignment", {}).get(
                        "has_mismatch", False
                    )
                    and (ml_score >= 50 or nlp_score >= 15)
                ),
            ]
        )

        # -----------------------------------------------------
        # Calculate score
        # -----------------------------------------------------

        score = (
            base_score
            + min(
                bonus_score,
                45,
            )
        )

        # Strong independent evidence should not become SAFE
        # merely because some components have no information.
        if (
            active_strong_signals >= 3
            and score < 60
        ):

            score = 60

            bonuses.append(
                "Multi-signal safety floor applied."
            )

        # Very suspicious domain + independent evidence.
        if (
            domain_score >= 80
            and (
                ml_score >= 50
                or nlp_score >= 40
            )
            and score < 70
        ):

            score = 70

            bonuses.append(
                "High-risk domain plus independent "
                "phishing evidence raised the minimum "
                "threat level."
            )

        # Strong NLP phishing pattern should not remain SAFE.
        if (
            nlp_score >= 70
            and score < 50
        ):

            score = 50

            bonuses.append(
                "Strong NLP phishing evidence raised "
                "the minimum threat level."
            )

        # Executables and macro-enabled files are high-risk content. Keep
        # the floor bounded so an otherwise empty message is reviewable,
        # while avoiding an unconditional critical verdict.
        if attachment_score >= 50 and score < 50:
            score = 50
            bonuses.append(
                "High-risk attachment raised the minimum threat level."
            )

        if (
            (header_res or {}).get("alignment", {}).get("has_mismatch", False)
            and (ml_score >= 50 or nlp_score >= 15)
            and score < 55
        ):
            score = 55
            bonuses.append(
                "Reply-To or return-path mismatch corroborates phishing evidence."
            )

        url_reasons = (url_res or {}).get("summary", {}).get("reasons", [])
        explicit_phishing_hostname = any(
            "explicit phishing or fake-site" in str(reason).lower()
            for reason in url_reasons
        )
        if explicit_phishing_hostname and score < 55:
            score = 55
            bonuses.append(
                "Explicit phishing hostname raised the minimum threat level."
            )

        if url_score >= 40 and nlp_score >= 30 and score < 55:
            score = 55
            bonuses.append(
                "Suspicious URL and content indicators agree."
            )

        # Strong BEC pattern.
        if (
            executive_present
            and financial_present
            and urgency_present
            and score < 65
        ):

            score = 65

            bonuses.append(
                "Executive impersonation, financial "
                "activity and urgency indicate probable BEC."
            )

        score = cls._clamp(
            score
        )

        # -----------------------------------------------------
        # Severity
        # -----------------------------------------------------

        if score >= 75:
            severity = "CRITICAL"

        elif score >= 50:
            severity = "HIGH"

        elif score >= 25:
            severity = "LOW"

        else:
            severity = "SAFE"

        # -----------------------------------------------------
        # Confidence
        # -----------------------------------------------------

        signal_values = [
            ml_score,
            nlp_score,
            domain_score,
            url_score,
            authentication_score,
            infrastructure_score,
        ]

        active_values = [
            value
            for value in signal_values
            if value > 0
        ]

        if not active_values:

            confidence = 0

        else:

            mean_strength = (
                sum(active_values)
                / len(active_values)
            )

            agreement_bonus = min(
                25,
                max(
                    0,
                    (
                        active_strong_signals
                        - 1
                    )
                    * 8,
                ),
            )

            confidence = cls._clamp(
                mean_strength * 0.75
                + agreement_bonus
            )

        # Strong domain + independent phishing evidence.
        if (
            domain_score >= 70
            and (
                ml_score >= 50
                or nlp_score >= 40
            )
        ):

            confidence = max(
                confidence,
                80,
            )

        # Strong NLP evidence.
        if nlp_score >= 70:
            confidence = max(
                confidence,
                70,
            )

        # Strong BEC evidence.
        if (
            executive_present
            and financial_present
            and urgency_present
        ):

            confidence = max(
                confidence,
                75,
            )

        # -----------------------------------------------------
        # Breakdown
        # -----------------------------------------------------

        breakdown = {
            "ml": ml_score,
            "nlp": nlp_score,
            "domain": domain_score,
            "url": url_score,
            "authentication": authentication_score,
            "infrastructure": infrastructure_score,
            "attachments": attachment_score,
        }

        weighted_contributions = {
            "ml": round(
                ml_score
                * cls.WEIGHTS["ml"],
                2,
            ),

            "nlp": round(
                nlp_score
                * cls.WEIGHTS["nlp"],
                2,
            ),

            "domain": round(
                domain_score
                * cls.WEIGHTS["domain"],
                2,
            ),

            "url": round(
                url_score
                * cls.WEIGHTS["url"],
                2,
            ),

            "authentication": round(
                authentication_score
                * cls.WEIGHTS["authentication"],
                2,
            ),

            "infrastructure": round(
                infrastructure_score
                * cls.WEIGHTS["infrastructure"],
                2,
            ),

            "attachments": round(
                attachment_score
                * cls.WEIGHTS["attachments"],
                2,
            ),
        }

        # -----------------------------------------------------
        # Return
        # -----------------------------------------------------

        return {
            "threat_score": score,

            "severity": severity,

            "confidence": confidence,

            "weights": cls.WEIGHTS,

            "breakdown": breakdown,

            "weighted_contributions":
                weighted_contributions,

            "base_score": round(
                base_score,
                2,
            ),

            "correlation_bonus": min(
                bonus_score,
                45,
            ),

            "correlation_findings": bonuses,

            "active_strong_signals":
                active_strong_signals,
        }