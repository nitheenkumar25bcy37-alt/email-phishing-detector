from __future__ import annotations

from typing import Any, Dict, Iterable, List


class RiskEngine:
    """Combines distinct findings without treating one signal as proof."""

    SEVERITY_WEIGHT = {"info": 0, "low": 8, "medium": 18, "high": 32, "critical": 45}

    @classmethod
    def evaluate(cls, findings: Iterable[Dict[str, Any]], nlp: Dict[str, Any] | None = None) -> Dict[str, Any]:
        findings = list(findings)
        seen_rules = set()
        contributions: List[Dict[str, Any]] = []
        score = 0.0
        confidence_values = []

        for finding in findings:
            rule = str(finding.get("rule", "unknown"))
            if rule in seen_rules:
                continue
            seen_rules.add(rule)
            severity = str(finding.get("severity", "info")).lower()
            confidence = max(0.0, min(1.0, float(finding.get("confidence", 0.0))))
            contribution = round(cls.SEVERITY_WEIGHT.get(severity, 0) * confidence, 2)
            score += contribution
            confidence_values.append(confidence)
            if contribution:
                contributions.append({"rule": rule, "points": contribution, "reason": finding.get("title", rule)})

        categories = (nlp or {}).get("categories", {})
        active = {key for key, values in categories.items() if values}
        if len(active) >= 2:
            score += 10
            contributions.append({"rule": "multi_signal_context", "points": 10, "reason": "Multiple independent social-engineering categories are present."})

        score = min(100, round(score))
        labels = {str(f.get("category", "")).lower() for f in findings}
        if "attachment" in labels and any(f.get("severity") in {"high", "critical"} for f in findings):
            classification = "Malware delivery"
        elif "bec" in labels or {"text", "sender identity"}.issubset(labels) and "financial_fraud" in active:
            classification = "Business Email Compromise"
        elif "url" in labels or "authentication" in labels:
            classification = "Credential phishing" if "credential_harvesting" in active else "Phishing"
        elif score >= 35:
            classification = "Suspicious but inconclusive"
        else:
            classification = "Legitimate or low risk"

        confidence = round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 0.0
        return {"risk_score": score, "confidence": confidence, "classification": classification, "contributions": contributions}
