from __future__ import annotations

import hashlib
from typing import Any, Dict, List
from uuid import uuid4

from backend.attachment_analyzer import AttachmentAnalyzer
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.nlp_engine import NLPEngine
from backend.parser import ForensicEmailParser
from backend.schemas.findings import AnalysisResult, EvidenceRecord, Finding
from backend.services.risk_engine import RiskEngine
from backend.services.origin_trace import OriginTraceService
from backend.intelligence.domain_provider import DomainIntelligenceProvider
from backend.intelligence.ip_provider import IPIntelligenceProvider

try:
    from backend.url_analyzer import URLAnalyzer
except Exception:
    URLAnalyzer = None


class AnalysisOrchestrator:
    """Pure, dependency-light v2 analysis pipeline."""

    VERSION = "4.0.0"

    def __init__(self, parser: ForensicEmailParser | None = None, ip_provider: IPIntelligenceProvider | None = None, domain_provider: DomainIntelligenceProvider | None = None):
        self.parser = parser or ForensicEmailParser()
        self.ip_provider = ip_provider or IPIntelligenceProvider()
        self.domain_provider = domain_provider or DomainIntelligenceProvider()

    @staticmethod
    def _finding(category: str, rule: str, severity: str, confidence: float, title: str, description: str, evidence: Dict[str, Any], limitations: List[str] | None = None) -> Finding:
        return Finding(category=category, rule=rule, severity=severity, confidence=confidence, title=title, description=description, evidence=evidence, limitations=limitations or [])

    def analyze(self, raw: bytes, source_type: str = "eml") -> AnalysisResult:
        if not raw:
            raise ValueError("Email content is empty")
        parsed = self.parser.parse_eml_bytes(raw)
        metadata = parsed.get("metadata", {}) or {}
        body = parsed.get("body", {}) or {}
        text = "\n".join(str(value) for value in (metadata.get("subject", ""), metadata.get("from", ""), body.get("plain", ""), body.get("html", "")))
        nlp = NLPEngine.analyze_text(text) or {}
        findings: List[Finding] = []
        categories = nlp.get("categories", nlp) or {}
        urgency = categories.get("urgency", []) or []
        credentials = categories.get("credential_harvesting", []) or []
        financial = categories.get("financial_fraud", []) or []
        social = categories.get("social_engineering", []) or []

        if urgency and (credentials or financial or social):
            findings.append(self._finding("Text", "contextual_social_engineering", "high", 0.84, "Urgency is combined with a high-risk request", "The message combines pressure with credential, financial, or authority cues.", {"urgency": urgency[:5], "related_categories": [key for key, value in (("credential_harvesting", credentials), ("financial_fraud", financial), ("social_engineering", social)) if value]}))
        elif urgency:
            findings.append(self._finding("Text", "urgency_only", "low", 0.62, "Urgency language detected", "Urgency alone is not proof of phishing and should be reviewed with other evidence.", {"cues": urgency[:5]}))
        if financial and social:
            findings.append(self._finding("BEC", "payment_authority_combination", "high", 0.82, "Financial request paired with authority cues", "The message combines a financial action with executive or confidentiality language.", {"financial": financial[:5], "social": social[:5]}))
        if credentials and parsed.get("urls"):
            findings.append(self._finding("Text", "credential_request_with_link", "high", 0.88, "Credential request includes a link", "Credential-related language is paired with one or more extracted URLs.", {"url_count": len(parsed.get("urls", [])), "credential_cues": credentials[:5]}))

        header = HeaderForensicAnalyzer.analyze(parsed) or {}
        findings.extend(header.get("findings", []))

        references = parsed.get("url_references", []) or [{"href": url, "visible_text": ""} for url in parsed.get("urls", [])]
        url_result = URLAnalyzer.analyze_references(references) if URLAnalyzer else {"findings": [], "urls": [], "highest_risk": 0}
        findings.extend(url_result.get("findings", []))

        attachment_result = AttachmentAnalyzer.analyze(parsed.get("attachments", []))
        findings.extend(attachment_result.get("findings", []))

        origin_trace = OriginTraceService.build(parsed, self.ip_provider)
        parsed["origin_trace"] = origin_trace
        findings.extend(origin_trace.get("findings", []))
        origin_domains = []
        for hop in parsed.get("network_chain", []):
            origin_domains.extend({"domain": hostname, "source": "received"} for hostname in hop.get("hostnames", []) if "." in str(hostname))
        metadata_domain = str(metadata.get("from", "")).split("@")[-1].strip("> ")
        if metadata_domain:
            origin_domains.append({"domain": metadata_domain, "source": "from"})
        domain_results = []
        for item in origin_domains:
            result = self.domain_provider.inspect(item["domain"], item["source"], [candidate["ip"] for candidate in origin_trace["origin_candidates"]])
            domain_results.append(result)
            findings.extend(result.get("findings", []))
        parsed["domain_intelligence"] = {"domains": domain_results, "limitations": ["DNS data is time-dependent and does not prove ownership or malicious intent."]}
        parsed["ip_intelligence"] = [candidate.get("intelligence") for candidate in origin_trace["origin_candidates"] if candidate.get("intelligence")]

        normalized_findings = [finding.model_dump() if hasattr(finding, "model_dump") else finding for finding in findings]
        risk = RiskEngine.evaluate(normalized_findings, nlp)
        limitations = ["Authentication success does not prove that a message is safe.", *OriginTraceService.LIMITATIONS, "IP and DNS intelligence is best-effort and provider-dependent."]
        evidence = EvidenceRecord(sha256=hashlib.sha256(raw).hexdigest(), byte_size=len(raw), analysis_version=self.VERSION, source_type=source_type)
        sanitized = dict(parsed)
        sanitized.pop("raw_bytes", None)
        return AnalysisResult(email_id=str(uuid4()), evidence=evidence, classification=risk["classification"], risk_score=risk["risk_score"], confidence=risk["confidence"], findings=findings, parsed=sanitized, limitations=limitations)
