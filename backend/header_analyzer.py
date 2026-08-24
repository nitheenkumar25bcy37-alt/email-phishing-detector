import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Dict, Optional

class HeaderAnalyzer:
    """Extracts relay paths, true origin IPs, and detects routing anomalies."""
    
    PRIVATE_IP_PATTERNS = [
        r'^10\.',
        r'^172\.(1[6-9]|2\d|3[01])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^::1$',
        r'^fc00:',
        r'^fe80:',
    ]

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Checks if an IP belongs to private/internal subnets (RFC 1918)."""
        for pattern in HeaderAnalyzer.PRIVATE_IP_PATTERNS:
            if re.match(pattern, ip):
                return True
        return False

    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extracts IPv4 and basic IPv6 addresses from a string."""
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return re.findall(ipv4_pattern, text)

    @staticmethod
    def extract_origin_ip(raw_headers: str) -> Optional[str]:
        """
        Parses Received headers from bottom to top to identify 
        the first non-private public IP address (the true sender origin).
        """
        lines = raw_headers.split('\n')
        received_headers = [line for line in lines if line.lower().startswith('received:')]
        
        # Parse from oldest hop (bottom) to newest hop (top)
        for header in reversed(received_headers):
            ips = HeaderAnalyzer.extract_ips(header)
            for ip in ips:
                if not HeaderAnalyzer.is_private_ip(ip):
                    return ip
        return None

    @staticmethod
    def detect_timestamp_anomalies(raw_headers: str) -> Dict:
        """
        Detects time-travel anomalies where timestamps on relay hops 
        move backwards, indicating forged or corrupted header records.
        """
        lines = raw_headers.split('\n')
        received_headers = [line for line in lines if line.lower().startswith('received:')]
        
        timestamps = []
        for header in received_headers:
            match = re.search(r';\s*(.+?)(?:\s*\(|$)', header)
            if match:
                try:
                    ts = parsedate_to_datetime(match.group(1))
                    timestamps.append(ts)
                except Exception:
                    pass

        anomalies = []
        for i in range(len(timestamps) - 1):
            if timestamps[i] < timestamps[i + 1]:
                delta = (timestamps[i + 1] - timestamps[i]).total_seconds()
                anomalies.append({
                    "type": "NEGATIVE_TIME_DELTA",
                    "seconds_difference": delta,
                    "severity": "CRITICAL" if delta > 3600 else "MEDIUM"
                })

        return {
            "total_hops": len(received_headers),
            "anomalies": anomalies,
            "is_suspicious": len(anomalies) > 0
        }
