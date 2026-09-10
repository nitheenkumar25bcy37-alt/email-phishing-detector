from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse

from backend.domain_intel import DomainForensics


class CampaignCorrelator:
    """Deterministic, evidence-based correlation for persisted analyses."""

    GENERIC_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "google.com", "cloudflare.com", "amazonaws.com"}
    GENERIC_ASNS = {"AS123", "AS13335", "AS15169", "AS16509"}
    STRONG_TYPES = {"shared_attachment_hash", "shared_url", "shared_sender", "shared_reply_to", "shared_origin_ip"}
    WEIGHTS = {
        "shared_attachment_hash": 0.98,
        "shared_url": 0.92,
        "shared_sender": 0.82,
        "shared_reply_to": 0.82,
        "shared_origin_ip": 0.78,
        "shared_relay_ip": 0.58,
        "shared_url_domain": 0.55,
        "shared_registered_domain": 0.48,
        "shared_message_id_domain": 0.38,
        "similar_subject": 0.42,
        "similar_body_structure": 0.35,
        "shared_impersonated_brand": 0.42,
        "shared_asn": 0.24,
        "shared_authentication_pattern": 0.34,
    }

    @staticmethod
    def _email_domain(value: Any) -> str:
        match = re.search(r"@([^>\s,]+)", str(value or ""))
        return match.group(1).lower().strip(".") if match else ""

    @staticmethod
    def _normalize_subject(value: Any) -> str:
        value = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", str(value or "").lower().strip())
        return re.sub(r"[^a-z0-9\s]", " ", value).strip()

    @staticmethod
    def _tokens(value: Any) -> Set[str]:
        return {token for token in re.findall(r"[a-z0-9]{3,}", str(value or "").lower()) if token not in {"the", "and", "for", "from", "with", "your"}}

    @classmethod
    def _jaccard(cls, left: Any, right: Any) -> float:
        a, b = cls._tokens(left), cls._tokens(right)
        return len(a & b) / len(a | b) if a and b else 0.0

    @classmethod
    def indicators(cls, analysis: Dict[str, Any]) -> Dict[str, Any]:
        parsed = analysis.get("parsed", {}) or {}
        metadata = parsed.get("metadata", {}) or {}
        body = parsed.get("body", {}) or {}
        sender = str(metadata.get("from", "")).lower().strip()
        reply_to = str(metadata.get("reply_to", "")).lower().strip()
        sender_domain = cls._email_domain(sender)
        reply_domain = cls._email_domain(reply_to)
        message_domain = cls._email_domain(metadata.get("message_id", ""))
        origin_trace = parsed.get("origin_trace", {}) or {}
        public_ips = {candidate.get("ip") for candidate in origin_trace.get("origin_candidates", []) if candidate.get("ip")}
        relay_ips = set()
        for hop in parsed.get("network_chain", []) or []:
            for ip, classification in zip(hop.get("extracted_ips", []), hop.get("ip_classifications", [])):
                if classification == "public":
                    relay_ips.add(ip)
        urls = {str(item.get("href") or item.get("normalized") or item) for item in parsed.get("url_references", []) or []}
        url_domains = set()
        for url in urls:
            try:
                hostname = (urlparse(url).hostname or "").lower()
                if hostname:
                    if hostname not in cls.GENERIC_DOMAINS:
                        url_domains.add(hostname)
            except ValueError:
                continue
        registered_domains = {DomainForensics._registered_domain(domain) for domain in {sender_domain, reply_domain, *url_domains} if domain}
        attachments = {item.get("sha256") for item in parsed.get("attachments", []) or [] if item.get("sha256")}
        brands = set()
        auth_pattern = []
        for finding in analysis.get("findings", []) or []:
            evidence = finding.get("evidence", {}) or {}
            for key in ("brand", "impersonated_brand", "display_name"):
                if evidence.get(key):
                    brands.add(str(evidence[key]).lower())
            if finding.get("rule", "").endswith("_failure"):
                auth_pattern.append(finding["rule"])
        for domain in parsed.get("domain_intelligence", {}).get("domains", []) or []:
            brands.update(str(item).lower() for item in domain.get("impersonated_brands", []) or [])
        ip_intelligence = parsed.get("ip_intelligence", []) or []
        asns = {str(item.get("asn")) for item in ip_intelligence if item.get("asn") and str(item.get("asn")) not in {"None", "Unknown"} and str(item.get("asn")) not in cls.GENERIC_ASNS}
        visible_text = body.get("visible_text") or body.get("plain", "")
        return {
            "sender": sender,
            "reply_to": reply_to,
            "sender_domain": sender_domain,
            "reply_to_domain": reply_domain,
            "registered_domains": {value for value in registered_domains if value},
            "origin_ips": public_ips,
            "relay_ips": relay_ips,
            "url_domains": url_domains,
            "urls": urls,
            "attachment_hashes": attachments,
            "message_id_domain": message_domain,
            "subject": cls._normalize_subject(metadata.get("subject", "")),
            "body_tokens": cls._tokens(visible_text),
            "brands": brands,
            "asns": asns,
            "auth_pattern": tuple(sorted(set(auth_pattern))),
        }

    @classmethod
    def correlate(cls, source_email_id: str, source: Dict[str, Any], candidates: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        source_indicators = cls.indicators(source)
        relationships = []
        for target in candidates:
            target_id = target.get("email_id")
            if not target_id or target_id == source_email_id:
                continue
            target_indicators = cls.indicators(target)
            evidence = []
            checks = [
                ("shared_sender", source_indicators["sender"], target_indicators["sender"], "Both emails use the same sender address."),
                ("shared_reply_to", source_indicators["reply_to"], target_indicators["reply_to"], "Both emails use the same Reply-To address."),
            ]
            for relationship_type, left, right, explanation in checks:
                if left and left == right:
                    evidence.append({"field": relationship_type, "source_value": left, "target_value": right, "explanation": explanation})
            for relationship_type, left_values, right_values, explanation in [
                ("shared_origin_ip", source_indicators["origin_ips"] - {"8.8.8.8", "1.1.1.1"}, target_indicators["origin_ips"] - {"8.8.8.8", "1.1.1.1"}, "Both emails share a public origin candidate."),
                ("shared_relay_ip", source_indicators["relay_ips"] - {"8.8.8.8", "1.1.1.1"}, target_indicators["relay_ips"] - {"8.8.8.8", "1.1.1.1"}, "Both emails share a public relay IP."),
                ("shared_url", source_indicators["urls"], target_indicators["urls"], "Both emails contain the same URL."),
                ("shared_url_domain", source_indicators["url_domains"], target_indicators["url_domains"], "Both emails reference the same URL domain."),
                ("shared_registered_domain", source_indicators["registered_domains"], target_indicators["registered_domains"], "Both emails reference the same registered domain."),
                ("shared_attachment_hash", source_indicators["attachment_hashes"], target_indicators["attachment_hashes"], "Both emails contain an attachment with the same SHA-256 hash."),
                ("shared_impersonated_brand", source_indicators["brands"], target_indicators["brands"], "Both emails contain evidence for the same impersonated organization."),
                ("shared_asn", source_indicators["asns"], target_indicators["asns"], "Both emails share an observed ASN."),
                ("shared_authentication_pattern", set(source_indicators["auth_pattern"]), set(target_indicators["auth_pattern"]), "Both emails share an authentication failure pattern."),
            ]:
                for value in sorted(left_values & right_values):
                    if relationship_type == "shared_registered_domain" and value in cls.GENERIC_DOMAINS:
                        continue
                    evidence.append({"field": relationship_type, "source_value": value, "target_value": value, "explanation": explanation})
                    break
            subject_score = cls._jaccard(source_indicators["subject"], target_indicators["subject"])
            if subject_score >= 0.8 and source_indicators["subject"] and target_indicators["subject"]:
                evidence.append({"field": "subject_similarity", "source_value": round(subject_score, 3), "target_value": round(subject_score, 3), "explanation": "Normalized subject structures are highly similar."})
            body_score = len(source_indicators["body_tokens"] & target_indicators["body_tokens"]) / len(source_indicators["body_tokens"] | target_indicators["body_tokens"]) if source_indicators["body_tokens"] and target_indicators["body_tokens"] else 0.0
            if body_score >= 0.8:
                evidence.append({"field": "body_structure_similarity", "source_value": round(body_score, 3), "target_value": round(body_score, 3), "explanation": "Visible body token structures are highly similar."})
            if not evidence:
                continue
            types = [item["field"] for item in evidence]
            strengths = [cls.WEIGHTS["similar_subject"] if item == "subject_similarity" else cls.WEIGHTS["similar_body_structure"] if item == "body_structure_similarity" else cls.WEIGHTS.get(item, 0.2) for item in types]
            strongest = max(strengths)
            confidence = min(0.99, round(strongest + 0.08 * (len(strengths) - 1), 3))
            if strongest < 0.35 and len(evidence) < 2:
                continue
            relationships.append({"source_email_id": source_email_id, "target_email_id": target_id, "relationship_type": max(zip(types, strengths), key=lambda pair: pair[1])[0], "confidence": confidence, "evidence": evidence, "limitations": ["A shared indicator does not prove that the same person sent both emails.", "Shared infrastructure can be reused by unrelated actors.", "This possible campaign relationship requires analyst confirmation."], "created_at": datetime.now(timezone.utc).isoformat(), "requires_review": True})
        return relationships
