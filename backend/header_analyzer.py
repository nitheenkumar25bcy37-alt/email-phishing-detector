"""
Agentic MX - Header & Authentication Forensics
Analyzes email headers for SPF, DKIM, DMARC, Return-Path/From mismatches, and hop anomalies.
"""

import re
from typing import Dict, Any, List

class HeaderAnalyzer:
    def __init__(self):
        self.ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def analyze(self, headers: Dict[str, Any], body_text: str = "") -> Dict[str, Any]:
        if not headers:
            return {
                "spf": "UNKNOWN",
                "dkim": "UNKNOWN",
                "dmarc": "UNKNOWN",
                "origin_ip": None,
                "hop_count": 0,
                "from_reply_to_mismatch": False,
                "from_return_path_mismatch": False,
                "anomalies": []
            }

        anomalies: List[str] = []

        # 1. Extract Addresses for Mismatch Analysis
        from_hdr = self._get_header_str(headers, "From")
        reply_to_hdr = self._get_header_str(headers, "Reply-To")
        return_path_hdr = self._get_header_str(headers, "Return-Path")

        from_addr = self._extract_email_addr(from_hdr)
        reply_to_addr = self._extract_email_addr(reply_to_hdr)
        return_path_addr = self._extract_email_addr(return_path_hdr)

        from_reply_mismatch = False
        if from_addr and reply_to_addr and from_addr.lower() != reply_to_addr.lower():
            from_reply_mismatch = True
            anomalies.append(f"Header mismatch: From ({from_addr}) != Reply-To ({reply_to_addr})")

        from_return_mismatch = False
        if from_addr and return_path_addr:
            from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
            return_domain = return_path_addr.split("@")[-1].lower() if "@" in return_path_addr else ""
            if from_domain and return_domain and from_domain != return_domain:
                from_return_mismatch = True
                anomalies.append(f"Domain mismatch: From domain ({from_domain}) != Return-Path domain ({return_domain})")

        # 2. Extract Authentication Results (SPF / DKIM / DMARC)
        auth_results = self._get_header_str(headers, "Authentication-Results").lower()
        received_spf = self._get_header_str(headers, "Received-SPF").lower()

        spf_status = self._parse_auth_status(auth_results, received_spf, "spf")
        dkim_status = self._parse_auth_status(auth_results, "", "dkim")
        dmarc_status = self._parse_auth_status(auth_results, "", "dmarc")

        # 3. Received Headers & Origin IP Forensics
        received_headers = headers.get("Received", [])
        if isinstance(received_headers, str):
            received_headers = [received_headers]

        hop_count = len(received_headers)
        origin_ip = None

        if received_headers:
            # Traversal from bottom-most Received header (closest to sender)
            for r_hdr in reversed(received_headers):
                ips = self.ip_regex.findall(str(r_hdr))
                for ip in ips:
                    if not self._is_private_ip(ip):
                        origin_ip = ip
                        break
                if origin_ip:
                    break

        if hop_count > 6:
            anomalies.append(f"Unusual routing chain length: {hop_count} hops detected")

        return {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "origin_ip": origin_ip,
            "hop_count": hop_count,
            "from_reply_to_mismatch": from_reply_mismatch,
            "from_return_path_mismatch": from_return_mismatch,
            "unusual_routing": len(anomalies) > 0,
            "anomalies": anomalies
        }

    def _get_header_str(self, headers: Dict[str, Any], key: str) -> str:
        val = headers.get(key, headers.get(key.lower(), ""))
        if isinstance(val, list):
            return " ".join(str(v) for v in val)
        return str(val)

    def _extract_email_addr(self, header_val: str) -> str:
        if "<" in header_val and ">" in header_val:
            return header_val.split("<")[1].split(">")[0].strip()
        return header_val.strip()

    def _parse_auth_status(self, auth_str: str, spf_str: str, protocol: str) -> str:
        combined = f"{auth_str} {spf_str}".lower()
        if not combined.strip():
            return "NONE"
        if f"{protocol}=pass" in combined or f"{protocol}: pass" in combined:
            return "PASS"
        if f"{protocol}=fail" in combined or f"{protocol}: fail" in combined or "softfail" in combined:
            return "FAIL"
        if f"{protocol}=neutral" in combined:
            return "NEUTRAL"
        return "UNKNOWN"

    def _is_private_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        first = int(parts[0]) if parts[0].isdigit() else 0
        second = int(parts[1]) if parts[1].isdigit() else 0
        if first == 10 or first == 127:
            return True
        if first == 172 and (16 <= second <= 31):
            return True
        if first == 192 and second == 168:
            return True
        return False
