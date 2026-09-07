"""
Indicator of Compromise (IOC) Extractor
Extracts email addresses, domains, IPs, URLs, and hashes from email content
"""

import re
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse


class IOCExtractor:
    """Extract indicators of compromise from email"""

    @staticmethod
    def extract(email_content: str, parsed_email: Dict) -> Dict[str, any]:
        """
        Extract all IOCs from email
        
        Args:
            email_content: Raw email string
            parsed_email: Parsed email dictionary from parser
            
        Returns:
            Dictionary with extracted IOCs
        """

        iocs = {
            "email_addresses": set(),
            "domains": set(),
            "urls": set(),
            "ip_addresses": set(),
            "file_hashes": set(),
            "phone_numbers": set(),
            "extracted_at": "",
            "summary": {}
        }

        body = parsed_email.get("body", "") + " " + parsed_email.get("subject", "")

        # 1. EXTRACT EMAIL ADDRESSES
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, body)
        iocs["email_addresses"] = set(emails)

        # 2. EXTRACT DOMAINS
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        domains = re.findall(domain_pattern, body)
        iocs["domains"] = set(d.lower() for d in domains)

        # 3. EXTRACT URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, body)
        iocs["urls"] = set(urls)

        # Extract domains from URLs
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    iocs["domains"].add(parsed.hostname.lower())
            except Exception:
                pass

        # 4. EXTRACT IP ADDRESSES
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ipv4s = re.findall(ipv4_pattern, body)
        iocs["ip_addresses"].update(set(ipv4s))

        # IPv6 (simplified)
        ipv6_pattern = r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}'
        ipv6s = re.findall(ipv6_pattern, body)
        iocs["ip_addresses"].update(set(ipv6s))

        # 5. EXTRACT FILE HASHES (MD5, SHA1, SHA256, SHA512)
        hash_patterns = {
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b',
            "sha512": r'\b[a-fA-F0-9]{128}\b'
        }

        for hash_type, pattern in hash_patterns.items():
            hashes = re.findall(pattern, body)
            for h in hashes:
                iocs["file_hashes"].add({
                    "hash": h,
                    "type": hash_type
                })

        # 6. EXTRACT PHONE NUMBERS (international format)
        phone_pattern = r'\+?[1-9]\d{1,14}'
        phones = re.findall(phone_pattern, body)
        iocs["phone_numbers"] = set(phones)

        # 7. SUMMARY COUNTS
        iocs["summary"] = {
            "email_count": len(iocs["email_addresses"]),
            "domain_count": len(iocs["domains"]),
            "url_count": len(iocs["urls"]),
            "ip_count": len(iocs["ip_addresses"]),
            "hash_count": len(iocs["file_hashes"]),
            "phone_count": len(iocs["phone_numbers"]),
            "total_iocs": (
                len(iocs["email_addresses"]) +
                len(iocs["domains"]) +
                len(iocs["urls"]) +
                len(iocs["ip_addresses"]) +
                len(iocs["file_hashes"]) +
                len(iocs["phone_numbers"])
            )
        }

        # Convert sets to lists for JSON serialization
        return IOCExtractor._serialize_iocs(iocs)

    @staticmethod
    def _serialize_iocs(iocs: Dict) -> Dict:
        """Convert sets to lists for JSON serialization"""

        serialized = {
            "email_addresses": sorted(list(iocs["email_addresses"])),
            "domains": sorted(list(iocs["domains"])),
            "urls": sorted(list(iocs["urls"])),
            "ip_addresses": sorted(list(iocs["ip_addresses"])),
            "file_hashes": [
                {
                    "hash": h.get("hash"),
                    "type": h.get("type")
                }
                for h in iocs["file_hashes"]
            ],
            "phone_numbers": sorted(list(iocs["phone_numbers"])),
            "summary": iocs["summary"]
        }

        return serialized

    @staticmethod
    def deduplicate_domains(domains: List[str]) -> List[str]:
        """Remove duplicate domains (case-insensitive)"""
        return list(set(d.lower() for d in domains if d))

    @staticmethod
    def filter_private_ips(ip_list: List[str]) -> List[str]:
        """Filter out private IP addresses"""

        private_ranges = [
            r'^10\.',
            r'^172\.(?:1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^0\.0\.0\.0',
            r'^255\.255\.255\.255',
            r'^localhost'
        ]

        public_ips = []
        for ip in ip_list:
            is_private = any(re.match(pattern, ip) for pattern in private_ranges)
            if not is_private:
                public_ips.append(ip)

        return public_ips
