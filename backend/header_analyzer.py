import re
from typing import Any, Dict


class HeaderForensicAnalyzer:
    @classmethod
    def analyze(cls, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        auth = parsed_email.get("authentication_headers", {})
        meta = parsed_email.get("metadata", {})
        chain = parsed_email.get("network_chain", [])

        auth_results = str(auth.get("authentication_results", "")).lower()
        spf_header = str(auth.get("spf_received", "")).lower()

        spf = cls._status("spf", auth_results, spf_header)
        dkim = cls._status("dkim", auth_results)
        dmarc = cls._status("dmarc", auth_results)

        from_domain = cls._domain(meta.get("from", ""))
        reply_domain = cls._domain(meta.get("reply_to", ""))
        return_domain = cls._domain(meta.get("return_path", ""))

        mismatches = []
        if from_domain and reply_domain and from_domain != reply_domain:
            mismatches.append(f"From domain ({from_domain}) != Reply-To domain ({reply_domain})")
        if from_domain and return_domain and from_domain != return_domain:
            mismatches.append(f"From domain ({from_domain}) != Return-Path domain ({return_domain})")

        score = 0
        indicators = []

        if spf == "fail":
            score += 25
            indicators.append("SPF validation failed")
        elif spf in {"none", "neutral"}:
            score += 5

        if dkim == "fail":
            score += 25
            indicators.append("DKIM result indicates failure")
        if dmarc == "fail":
            score += 30
            indicators.append("DMARC result indicates failure")
        if mismatches:
            score += min(20, 10 * len(mismatches))
            indicators.extend(mismatches)

        origin_ip = chain[0].get("originating_ip") if chain else None

        return {
            "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
            "alignment": {
                "from_domain": from_domain,
                "reply_to_domain": reply_domain,
                "return_path_domain": return_domain,
                "has_mismatch": bool(mismatches),
            },
            "originating_ip": origin_ip,
            "hop_count": len(chain),
            "header_risk_score": min(score, 100),
            "indicators": indicators,
        }

    @staticmethod
    def _status(kind: str, *values: str) -> str:
        combined = " ".join(values).lower()
        if re.search(rf"\b{kind}=(pass|bestguesspass)\b", combined):
            return "pass"
        if re.search(rf"\b{kind}=(fail|softfail|temperror|permerror)\b", combined):
            return "fail"
        return "none"

    @staticmethod
    def _domain(value: str) -> str:
        match = re.search(r"@([A-Za-z0-9.-]+)", str(value))
        return match.group(1).lower().strip(".") if match else ""
