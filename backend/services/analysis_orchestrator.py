from __future__ import annotations

import hashlib
from typing import Any, Dict, List
from uuid import uuid4

from backend.attachment_analyzer import AttachmentAnalyzer
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.nlp_engine import NLPEngine
from backend.parser import ForensicEmailParser

from backend.schemas.findings import (
    AnalysisResult,
    EvidenceRecord,
    Finding,
)

from backend.services.risk_engine import RiskEngine
from backend.services.origin_trace import OriginTraceService

from backend.intelligence.domain_provider import (
    DomainIntelligenceProvider,
)

from backend.intelligence.ip_provider import (
    IPIntelligenceProvider,
)

from backend.multilingual_detector import (
    MultilingualLanguageDetector,
)

try:
    from backend.url_analyzer import URLAnalyzer
except Exception:
    URLAnalyzer = None
class AnalysisOrchestrator:
    """
    Pure, dependency-light v2 analysis pipeline.

    Multilingual support:
    - Detects supported Indian languages.
    - Preserves the original NLP engine.
    - Adds multilingual contextual evidence.
    - Avoids double-counting multilingual findings.
    - Exposes multilingual_score consistently in the V2 result.
    - Language alone is never considered malicious.
    """

    VERSION = "4.1.0"

    def __init__(
        self,
        parser: ForensicEmailParser | None = None,
        ip_provider: IPIntelligenceProvider | None = None,
        domain_provider: DomainIntelligenceProvider | None = None,
    ):
        self.parser = parser or ForensicEmailParser()
        self.ip_provider = ip_provider or IPIntelligenceProvider()
        self.domain_provider = domain_provider or DomainIntelligenceProvider()

    # ------------------------------------------------------------------
    # FINDING FACTORY
    # ------------------------------------------------------------------

    @staticmethod
    def _finding(
        category: str,
        rule: str,
        severity: str,
        confidence: float,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        limitations: List[str] | None = None,
    ) -> Finding:
        return Finding(
            category=category,
            rule=rule,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence=evidence,
            limitations=limitations or [],
        )

    # ------------------------------------------------------------------
    # MULTILINGUAL NLP MERGE
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_multilingual_categories(
        nlp: Dict[str, Any],
        multilingual: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge multilingual Indian-language findings into the existing
        NLP result without replacing the original NLP analysis.
        """

        existing_categories = nlp.get("categories", {}) or {}

        merged_categories = {
            category: list(values or [])
            for category, values in existing_categories.items()
        }

        multilingual_categories = (
            multilingual.get("multilingual_findings", {}) or {}
        )

        for category, indicators in multilingual_categories.items():
            if not indicators:
                continue

            current = merged_categories.setdefault(category, [])

            for indicator in indicators:
                if indicator not in current:
                    current.append(indicator)

        nlp["categories"] = merged_categories

        # Preserve multilingual metadata.
        nlp["language"] = multilingual.get(
            "language",
            "Unknown",
        )

        nlp["language_code"] = multilingual.get(
            "language_code",
            "und",
        )

        nlp["language_confidence"] = multilingual.get(
            "language_confidence",
            0.0,
        )

        nlp["script"] = multilingual.get(
            "script",
            "unknown",
        )

        nlp["is_multilingual"] = multilingual.get(
            "is_multilingual",
            False,
        )

        nlp["detection_method"] = multilingual.get(
            "detection_method",
            "",
        )

        nlp["detected_scripts"] = multilingual.get(
            "detected_scripts",
            [],
        )

        nlp["multilingual_findings"] = multilingual_categories

        # IMPORTANT:
        # Keep the canonical key as multilingual_score.
        nlp["multilingual_score"] = int(
            multilingual.get(
                "multilingual_score",
                0,
            )
            or 0
        )

        return nlp

    # ------------------------------------------------------------------
    # MULTILINGUAL FINDINGS
    # ------------------------------------------------------------------

    def _build_multilingual_findings(
        self,
        multilingual: Dict[str, Any],
    ) -> List[Finding]:
        """
        Convert multilingual detector results into normal V2 Finding
        objects.

        Language itself is never treated as malicious.
        Only contextual threat indicators generate findings.
        """

        findings: List[Finding] = []

        multilingual_score = int(
            multilingual.get(
                "multilingual_score",
                0,
            )
            or 0
        )

        language = multilingual.get(
            "language",
            "Unknown",
        )

        language_code = multilingual.get(
            "language_code",
            "und",
        )

        script = multilingual.get(
            "script",
            "unknown",
        )

        categories = (
            multilingual.get(
                "multilingual_findings",
                {},
            )
            or {}
        )

        urgency = categories.get(
            "urgency",
            [],
        ) or []

        credentials = categories.get(
            "credential_harvesting",
            [],
        ) or []

        financial = categories.get(
            "financial_fraud",
            [],
        ) or []

        social = categories.get(
            "social_engineering",
            [],
        ) or []

        # No threat indicators -> no multilingual finding.
        if not any(
            (
                urgency,
                credentials,
                financial,
                social,
            )
        ):
            return findings

        related_categories = []

        if urgency:
            related_categories.append(
                "urgency"
            )

        if credentials:
            related_categories.append(
                "credential_harvesting"
            )

        if financial:
            related_categories.append(
                "financial_fraud"
            )

        if social:
            related_categories.append(
                "social_engineering"
            )

        # --------------------------------------------------------------
        # STRONG CONTEXTUAL COMBINATION
        # --------------------------------------------------------------

        if urgency and (
            credentials
            or financial
            or social
        ):
            findings.append(
                self._finding(
                    "Text",
                    "multilingual_contextual_social_engineering",
                    "high",
                    0.84,
                    "Multilingual urgency is combined with a high-risk request",
                    (
                        "The message contains supported Indian-language "
                        "or multilingual urgency cues together with "
                        "credential, financial, or social-engineering "
                        "indicators."
                    ),
                    {
                        "language": language,
                        "language_code": language_code,
                        "script": script,
                        "multilingual_score": multilingual_score,
                        "categories": related_categories,
                        "urgency": urgency[:5],
                        "credential_cues": credentials[:5],
                        "financial_cues": financial[:5],
                        "social_cues": social[:5],
                    },
                )
            )

        # --------------------------------------------------------------
        # FINANCIAL FRAUD WITHOUT URGENCY
        # --------------------------------------------------------------

        elif financial:
            findings.append(
                self._finding(
                    "Text",
                    "multilingual_financial_fraud",
                    "medium",
                    0.72,
                    "Financial-risk language detected",
                    (
                        "The message contains financial-risk "
                        "indicators detected in a supported "
                        "Indian language."
                    ),
                    {
                        "language": language,
                        "language_code": language_code,
                        "script": script,
                        "multilingual_score": multilingual_score,
                        "financial_cues": financial[:5],
                    },
                )
            )

        # --------------------------------------------------------------
        # CREDENTIAL HARVESTING WITHOUT URGENCY
        # --------------------------------------------------------------

        if credentials and not urgency:
            findings.append(
                self._finding(
                    "Text",
                    "multilingual_credential_harvesting",
                    "medium",
                    0.76,
                    "Credential-harvesting language detected",
                    (
                        "The message contains credential-related "
                        "language detected in a supported "
                        "Indian language."
                    ),
                    {
                        "language": language,
                        "language_code": language_code,
                        "script": script,
                        "multilingual_score": multilingual_score,
                        "credential_cues": credentials[:5],
                    },
                )
            )

        return findings

    # ------------------------------------------------------------------
    # MAIN ANALYSIS PIPELINE
    # ------------------------------------------------------------------

    def analyze(
        self,
        raw: bytes,
        source_type: str = "eml",
    ) -> AnalysisResult:

        if not raw:
            raise ValueError(
                "Email content is empty"
            )

        # ==============================================================
        # 1. FORENSIC PARSING
        # ==============================================================

        parsed = self.parser.parse_eml_bytes(
            raw
        )

        metadata = parsed.get(
            "metadata",
            {},
        ) or {}

        body = parsed.get(
            "body",
            {},
        ) or {}

        text = "\n".join(
            str(value)
            for value in (
                metadata.get(
                    "subject",
                    "",
                ),
                metadata.get(
                    "from",
                    "",
                ),
                body.get(
                    "plain",
                    "",
                ),
                body.get(
                    "html",
                    "",
                ),
            )
        )

        # ==============================================================
        # 2. EXISTING NLP
        # ==============================================================

        nlp = (
            NLPEngine.analyze_text(
                text
            )
            or {}
        )

        # Keep a copy of the original English NLP categories.
        #
        # This is important because multilingual categories should not
        # cause the original English contextual rules to fire twice.
        original_categories = {
            category: list(values or [])
            for category, values in (
                nlp.get(
                    "categories",
                    {},
                )
                or {}
            ).items()
        }

        # ==============================================================
        # 3. MULTILINGUAL INDIAN-LANGUAGE ANALYSIS
        # ==============================================================

        try:
            multilingual = (
                MultilingualLanguageDetector.analyze(
                    text or ""
                )
                or {}
            )

        except Exception:
            # Multilingual detection must NEVER break V2 analysis.
            multilingual = {
                "language": "Unknown",
                "language_code": "und",
                "language_confidence": 0.0,
                "script": "unknown",
                "is_multilingual": False,
                "detection_method": "error_fallback",
                "detected_scripts": [],
                "multilingual_findings": {},
                "multilingual_score": 0,
            }

        # Merge multilingual information into NLP.
        nlp = self._merge_multilingual_categories(
            nlp,
            multilingual,
        )

        multilingual_score = int(
            multilingual.get(
                "multilingual_score",
                0,
            )
            or 0
        )

        # ==============================================================
        # 4. FINDINGS
        # ==============================================================

        findings: List[Finding] = []

        # --------------------------------------------------------------
        # MULTILINGUAL FINDINGS
        # --------------------------------------------------------------

        findings.extend(
            self._build_multilingual_findings(
                multilingual
            )
        )

        # ==============================================================
        # 5. EXISTING NLP CATEGORIES
        #
        # IMPORTANT:
        # Use ONLY the ORIGINAL NLP categories here.
        #
        # Otherwise:
        #
        # multilingual finding
        # +
        # contextual_social_engineering
        #
        # would both represent the same evidence.
        # ==============================================================

        urgency = original_categories.get(
            "urgency",
            [],
        ) or []

        credentials = original_categories.get(
            "credential_harvesting",
            [],
        ) or []

        financial = original_categories.get(
            "financial_fraud",
            [],
        ) or []

        social = original_categories.get(
            "social_engineering",
            [],
        ) or []

        # ==============================================================
        # 6. EXISTING ENGLISH CONTEXTUAL RULES
        # ==============================================================

        if urgency and (
            credentials
            or financial
            or social
        ):
            findings.append(
                self._finding(
                    "Text",
                    "contextual_social_engineering",
                    "high",
                    0.84,
                    "Urgency is combined with a high-risk request",
                    (
                        "The message combines pressure with "
                        "credential, financial, or authority cues."
                    ),
                    {
                        "urgency": urgency[:5],
                        "related_categories": [
                            key
                            for key, value in (
                                (
                                    "credential_harvesting",
                                    credentials,
                                ),
                                (
                                    "financial_fraud",
                                    financial,
                                ),
                                (
                                    "social_engineering",
                                    social,
                                ),
                            )
                            if value
                        ],
                    },
                )
            )

        elif urgency:
            findings.append(
                self._finding(
                    "Text",
                    "urgency_only",
                    "low",
                    0.62,
                    "Urgency language detected",
                    (
                        "Urgency alone is not proof of phishing "
                        "and should be reviewed with other evidence."
                    ),
                    {
                        "cues": urgency[:5],
                    },
                )
            )

        if financial and social:
            findings.append(
                self._finding(
                    "BEC",
                    "payment_authority_combination",
                    "high",
                    0.82,
                    "Financial request paired with authority cues",
                    (
                        "The message combines a financial action "
                        "with executive or confidentiality language."
                    ),
                    {
                        "financial": financial[:5],
                        "social": social[:5],
                    },
                )
            )

        if credentials and parsed.get(
            "urls"
        ):
            findings.append(
                self._finding(
                    "Text",
                    "credential_request_with_link",
                    "high",
                    0.88,
                    "Credential request includes a link",
                    (
                        "Credential-related language is paired "
                        "with one or more extracted URLs."
                    ),
                    {
                        "url_count": len(
                            parsed.get(
                                "urls",
                                [],
                            )
                        ),
                        "credential_cues": credentials[:5],
                    },
                )
            )

        # ==============================================================
        # 7. HEADER FORENSICS
        # ==============================================================

        header = (
            HeaderForensicAnalyzer.analyze(
                parsed
            )
            or {}
        )

        findings.extend(
            header.get(
                "findings",
                [],
            )
        )

        # ==============================================================
        # 8. URL ANALYSIS
        # ==============================================================

        references = (
            parsed.get(
                "url_references",
                [],
            )
            or [
                {
                    "href": url,
                    "visible_text": "",
                }
                for url in parsed.get(
                    "urls",
                    [],
                )
            ]
        )

        url_result = (
            URLAnalyzer.analyze_references(
                references
            )
            if URLAnalyzer
            else {
                "findings": [],
                "urls": [],
                "highest_risk": 0,
            }
        )

        findings.extend(
            url_result.get(
                "findings",
                []
            )
        )

        # ==============================================================
        # 9. ATTACHMENT ANALYSIS
        # ==============================================================

        attachment_result = (
            AttachmentAnalyzer.analyze(
                parsed.get(
                    "attachments",
                    [],
                )
            )
        )

        findings.extend(
            attachment_result.get(
                "findings",
                [],
            )
        )

        # ==============================================================
        # 10. ORIGIN TRACE
        # ==============================================================

        origin_trace = (
            OriginTraceService.build(
                parsed,
                self.ip_provider,
            )
        )

        parsed["origin_trace"] = (
            origin_trace
        )

        findings.extend(
            origin_trace.get(
                "findings",
                [],
            )
        )

        # ==============================================================
        # 11. DOMAIN INTELLIGENCE
        # ==============================================================

        origin_domains = []

        for hop in parsed.get(
            "network_chain",
            [],
        ):
            origin_domains.extend(
                {
                    "domain": hostname,
                    "source": "received",
                }
                for hostname in hop.get(
                    "hostnames",
                    [],
                )
                if "." in str(
                    hostname
                )
            )

        metadata_domain = (
            str(
                metadata.get(
                    "from",
                    "",
                )
            )
            .split("@")[-1]
            .strip("> ")
        )

        if metadata_domain:
            origin_domains.append(
                {
                    "domain": metadata_domain,
                    "source": "from",
                }
            )

        domain_results = []

        for item in origin_domains:
            result = (
                self.domain_provider.inspect(
                    item["domain"],
                    item["source"],
                    [
                        candidate["ip"]
                        for candidate in origin_trace.get(
                            "origin_candidates",
                            [],
                        )
                    ],
                )
            )

            domain_results.append(
                result
            )

            findings.extend(
                result.get(
                    "findings",
                    [],
                )
            )

        parsed["domain_intelligence"] = {
            "domains": domain_results,
            "limitations": [
                (
                    "DNS data is time-dependent and does "
                    "not prove ownership or malicious intent."
                )
            ],
        }

        # ==============================================================
        # 12. IP INTELLIGENCE
        # ==============================================================

        parsed["ip_intelligence"] = [
            candidate.get(
                "intelligence"
            )
            for candidate in origin_trace.get(
                "origin_candidates",
                [],
            )
            if candidate.get(
                "intelligence"
            )
        ]

        # ==============================================================
        # 13. NORMALIZE FINDINGS
        # ==============================================================

        normalized_findings = [
            (
                finding.model_dump()
                if hasattr(
                    finding,
                    "model_dump",
                )
                else finding
            )
            for finding in findings
        ]

        # ==============================================================
        # 14. FINAL RISK ENGINE
        # ==============================================================

        risk = RiskEngine.evaluate(
            normalized_findings,
            nlp,
        )

        # ==============================================================
        # 15. MULTILINGUAL RESULT
        #
        # Keep BOTH names for compatibility:
        #
        # multilingual_score
        # score
        #
        # "multilingual_score" is the canonical field.
        # ==============================================================

        parsed["multilingual_analysis"] = {
            "language": multilingual.get(
                "language",
                "Unknown",
            ),
            "language_code": multilingual.get(
                "language_code",
                "und",
            ),
            "language_confidence": multilingual.get(
                "language_confidence",
                0.0,
            ),
            "script": multilingual.get(
                "script",
                "unknown",
            ),
            "is_multilingual": multilingual.get(
                "is_multilingual",
                False,
            ),
            "detection_method": multilingual.get(
                "detection_method",
                "",
            ),
            "detected_scripts": multilingual.get(
                "detected_scripts",
                [],
            ),
            "findings": multilingual.get(
                "multilingual_findings",
                {},
            ),
            "multilingual_findings": multilingual.get(
                "multilingual_findings",
                {},
            ),
            "multilingual_score": multilingual_score,
            "score": multilingual_score,
        }

        # ==============================================================
        # 16. NLP MULTILINGUAL METADATA
        # ==============================================================

        parsed["nlp_multilingual"] = {
            "language": multilingual.get(
                "language",
                "Unknown",
            ),
            "language_code": multilingual.get(
                "language_code",
                "und",
            ),
            "language_confidence": multilingual.get(
                "language_confidence",
                0.0,
            ),
            "script": multilingual.get(
                "script",
                "unknown",
            ),
            "multilingual_score": multilingual_score,
        }

        # ==============================================================
        # 17. LIMITATIONS
        # ==============================================================

        limitations = [
            (
                "Authentication success does not prove "
                "that a message is safe."
            ),
            *OriginTraceService.LIMITATIONS,
            (
                "IP and DNS intelligence is best-effort "
                "and provider-dependent."
            ),
            (
                "Multilingual language detection provides "
                "contextual evidence and does not by itself "
                "prove malicious intent."
            ),
        ]

        # ==============================================================
        # 18. EVIDENCE RECORD
        # ==============================================================

        evidence = EvidenceRecord(
            sha256=hashlib.sha256(
                raw
            ).hexdigest(),
            byte_size=len(raw),
            analysis_version=self.VERSION,
            source_type=source_type,
        )

        # ==============================================================
        # 19. SANITIZE PARSED RESULT
        # ==============================================================

        sanitized = dict(
            parsed
        )

        sanitized.pop(
            "raw_bytes",
            None,
        )

        # ==============================================================
        # 20. FINAL V2 RESULT
        # ==============================================================

        return AnalysisResult(
            email_id=str(
                uuid4()
            ),
            evidence=evidence,
            classification=risk[
                "classification"
            ],
            risk_score=risk[
                "risk_score"
            ],
            confidence=risk[
                "confidence"
            ],
            findings=findings,
            parsed=sanitized,
            limitations=limitations,
        )