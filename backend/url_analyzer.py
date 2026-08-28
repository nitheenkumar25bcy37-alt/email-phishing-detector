"""
URL Analyzer for Email Phishing Detection
Advanced static analysis of URLs without visiting them
Detects brand impersonation, typosquatting, suspicious keywords, and structural anomalies
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Tuple, Optional
import hashlib
import difflib


class URLAnalyzer:
    """Comprehensive static URL threat analysis"""

    # Known legitimate brands (domain only, no www)
    LEGITIMATE_BRANDS = {
        "paypal.com": {"name": "PayPal", "alternatives": ["paypalcorp.com"]},
        "microsoft.com": {"name": "Microsoft", "alternatives": ["microsoft.com"]},
        "apple.com": {"name": "Apple", "alternatives": ["apple.com"]},
        "google.com": {"name": "Google", "alternatives": ["google.com", "googlemail.com"]},
        "amazon.com": {"name": "Amazon", "alternatives": ["amazon.com"]},
        "facebook.com": {"name": "Facebook", "alternatives": ["fb.com", "instagram.com", "whatsapp.com"]},
        "twitter.com": {"name": "Twitter", "alternatives": ["twitter.com", "x.com"]},
        "linkedin.com": {"name": "LinkedIn", "alternatives": ["linkedin.com"]},
        "github.com": {"name": "GitHub", "alternatives": ["github.com"]},
        "sbi.co.in": {"name": "SBI", "alternatives": ["sbionline.sbi"]},
        "hdfc.com": {"name": "HDFC", "alternatives": ["hdfcbank.com"]},
        "icicibank.com": {"name": "ICICI", "alternatives": ["icici.co.in"]},
        "axisbank.com": {"name": "Axis", "alternatives": ["axisbank.com"]},
        "kotakbank.com": {"name": "Kotak", "alternatives": ["kotakbank.com"]},
        "upi.npci.org.in": {"name": "UPI", "alternatives": ["npci.org.in"]},
        "aadharonline.uidai.gov.in": {"name": "Aadhaar", "alternatives": ["uidai.gov.in"]},
        "incometaxindiaefiling.gov.in": {"name": "Income Tax", "alternatives": ["incometax.gov.in"]},
        "gst.gov.in": {"name": "GST", "alternatives": ["gst.gov.in"]},
    }

    # URL shortener services
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "short.link",
        "rebrand.ly", "bitly.com", "t.co", "is.gd", "buff.ly",
        "su.pr", "adf.ly", "j.mp", "shorten.link", "0.io"
    }

    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = {
        "verify": 8,
        "login": 7,
        "signin": 7,
        "account": 6,
        "update": 6,
        "confirm": 7,
        "security": 5,
        "password": 8,
        "reset": 6,
        "urgent": 7,
        "action": 5,
        "validate": 7,
        "authorization": 7,
        "authenticate": 7,
        "payment": 6,
        "billing": 6,
        "invoice": 5,
        "receipt": 4,
        "click-here": 6,
        "click": 4,
        "now": 3,
        "here": 2,
        "urgent": 7,
        "expire": 6,
        "expire-soon": 7,
        "limited-time": 6,
        "final-notice": 7,
    }

    # Suspicious TLDs (including country-specific high-risk ones)
    SUSPICIOUS_TLDS = {
        ".tk": True,  # Free TLD, commonly abused
        ".ml": True,  # Mali, free registrations
        ".ga": True,  # Gabon, free registrations
        ".cf": True,  # Central African Republic, free
        ".gq": True,  # Equatorial Guinea, free
        ".date": True,
        ".download": True,
        ".men": True,
        ".online": True,
        ".space": True,
        ".stream": True,
        ".website": True,
    }

    @staticmethod
    def analyze(urls: List[str]) -> Dict[str, any]:
        """
        Analyze list of URLs for threats
        
        Args:
            urls: List of URL strings extracted from email
            
        Returns:
            Dictionary with analysis results
        """
        if not urls:
            return {
                "urls_found": [],
                "suspicious_urls": [],
                "risk_score": 0,
                "risk_level": "LOW"
            }

        suspicious_urls = []
        total_risk = 0
        max_risk = 0

        for url in urls:
            analysis = URLAnalyzer._analyze_single_url(url)
            total_risk += analysis.get("risk_score", 0)
            max_risk = max(max_risk, analysis.get("risk_score", 0))

            if analysis.get("risk_level") != "LOW":
                suspicious_urls.append(analysis)

        # Calculate overall risk
        avg_risk = (total_risk // len(urls)) if urls else 0
        risk_level = URLAnalyzer._risk_level_from_score(max_risk)

        return {
            "urls_found": urls,
            "suspicious_urls": suspicious_urls,
            "risk_score": min(max_risk, 20),  # Max 20 points for threat scoring
            "risk_level": risk_level,
            "analysis_count": len(urls),
            "suspicious_count": len(suspicious_urls)
        }

    @staticmethod
    def _analyze_single_url(url: str) -> Dict[str, any]:
        """Analyze a single URL for threats"""

        if not url:
            return {
                "url": url,
                "risk_score": 0,
                "risk_level": "LOW",
                "indicators": []
            }

        indicators = []
        risk_score = 0

        try:
            # 1. URL VALIDATION & PARSING
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname or parsed.netloc
            path = parsed.path or ""
            query = parsed.query or ""

            if not hostname:
                return {
                    "url": url,
                    "risk_score": 15,
                    "risk_level": "MEDIUM",
                    "indicators": ["Malformed URL - no hostname"]
                }

            hostname_lower = hostname.lower()

            # 2. CHECK FOR HTTPS
            if scheme == "http":
                risk_score += 3
                indicators.append("No HTTPS encryption (HTTP)")

            # 3. CHECK FOR RAW IP ADDRESS
            if URLAnalyzer._is_ip_address(hostname):
                risk_score += 8
                indicators.append(f"Raw IP address URL: {hostname}")

            # 4. CHECK FOR USERINFO TRICK (username:password@host)
            if "@" in url and scheme in ["http", "https"]:
                # Extract the part before @
                before_at = url.split("://")[1].split("@")[0] if "://" in url else ""
                if ":" in before_at or before_at:
                    risk_score += 7
                    indicators.append("URL contains userinfo (username@host trick)")

            # 5. CHECK FOR URL SHORTENERS
            if URLAnalyzer._is_shortener(hostname_lower):
                risk_score += 6
                indicators.append(f"URL shortener detected: {hostname}")

            # 6. CHECK FOR PUNYCODE/IDN
            if "xn--" in hostname_lower:
                risk_score += 5
                indicators.append(f"Punycode/IDN domain detected: {hostname}")

            # 7. EXTRACT REGISTRABLE DOMAIN
            registrable_domain = URLAnalyzer._get_registrable_domain(hostname_lower)

            # 8. CHECK FOR BRAND IMPERSONATION
            impersonation_check = URLAnalyzer._check_brand_impersonation(
                hostname_lower, registrable_domain
            )
            if impersonation_check.get("impersonated"):
                risk_score += impersonation_check.get("score", 5)
                indicators.append(
                    f"Brand impersonation: {impersonation_check.get('brand_name')} "
                    f"({impersonation_check.get('reason')})"
                )

            # 9. CHECK FOR TYPOSQUATTING
            typo_check = URLAnalyzer._check_typosquatting(registrable_domain)
            if typo_check.get("is_typo"):
                risk_score += typo_check.get("score", 4)
                indicators.append(
                    f"Possible typosquatting: similar to {typo_check.get('similar_to')}"
                )

            # 10. EXCESSIVE SUBDOMAINS
            subdomain_count = hostname_lower.count(".")
            if subdomain_count > 5:
                risk_score += 3
                indicators.append(f"Excessive subdomains ({subdomain_count})")

            # 11. HOSTNAME LENGTH
            if len(hostname) > 60:
                risk_score += 2
                indicators.append(f"Unusually long hostname ({len(hostname)} chars)")

            # 12. SUSPICIOUS KEYWORDS IN PATH/QUERY
            keyword_score = URLAnalyzer._check_suspicious_keywords(
                path + "?" + query
            )
            if keyword_score > 0:
                risk_score += min(keyword_score, 4)
                indicators.append("Suspicious keywords in URL path/query")

            # 13. SUSPICIOUS TLD
            tld = URLAnalyzer._extract_tld(hostname)
            if tld in URLAnalyzer.SUSPICIOUS_TLDS:
                risk_score += 3
                indicators.append(f"Suspicious TLD: {tld}")

            # 14. ENCODED CHARACTERS IN URL
            if "%" in url:
                decoded = unquote(url)
                if decoded != url:
                    risk_score += 2
                    indicators.append("URL contains encoded characters")

            # 15. PORT ANOMALIES
            if parsed.port:
                if parsed.port not in [80, 443, 8080]:
                    risk_score += 2
                    indicators.append(f"Non-standard port: {parsed.port}")

        except Exception as e:
            indicators.append(f"Error analyzing URL: {str(e)}")
            risk_score = 5

        # Cap score at 20 for URL intelligence component
        risk_score = min(risk_score, 20)
        risk_level = URLAnalyzer._risk_level_from_score(risk_score)

        return {
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "registrable_domain": registrable_domain,
            "indicators": indicators
        }

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Check if hostname is a raw IP address"""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, hostname):
            parts = hostname.split(".")
            return all(0 <= int(part) <= 255 for part in parts)

        # IPv6 pattern (simplified)
        if ":" in hostname and re.match(r'^[0-9a-f:]+$', hostname.lower()):
            return True

        return False

    @staticmethod
    def _is_shortener(hostname: str) -> bool:
        """Check if URL is a shortener service"""
        # Remove www prefix
        clean_hostname = hostname.replace("www.", "")
        return clean_hostname in URLAnalyzer.URL_SHORTENERS

    @staticmethod
    def _get_registrable_domain(hostname: str) -> str:
        """
        Extract registrable domain (last two labels)
        e.g., "sub.paypal.com" -> "paypal.com"
        """
        parts = hostname.split(".")
        if len(parts) < 2:
            return hostname

        # Simple extraction (last 2 labels)
        # More sophisticated: use public suffix list
        return ".".join(parts[-2:])

    @staticmethod
    def _check_brand_impersonation(hostname: str, registrable_domain: str) -> Dict:
        """Detect brand impersonation in hostname"""

        # Check if registrable domain is legitimate
        if registrable_domain in URLAnalyzer.LEGITIMATE_BRANDS:
            return {"impersonated": False}

        # Check for similar brands using fuzzy matching
        for legit_domain, brand_info in URLAnalyzer.LEGITIMATE_BRANDS.items():
            brand_name = brand_info.get("name")

            # Direct match in hostname (not registrable domain)
            if brand_name.lower() in hostname:
                # But registrable domain is different = impersonation
                if registrable_domain != legit_domain:
                    return {
                        "impersonated": True,
                        "brand_name": brand_name,
                        "reason": "Brand name in URL but different registrable domain",
                        "legitimate_domain": legit_domain,
                        "suspicious_domain": registrable_domain,
                        "score": 10
                    }

            # Check alternatives
            alternatives = brand_info.get("alternatives", [])
            if registrable_domain in alternatives:
                return {"impersonated": False}

        return {"impersonated": False}

    @staticmethod
    def _check_typosquatting(registrable_domain: str) -> Dict:
        """Detect typosquatting attacks"""

        legit_domains = list(URLAnalyzer.LEGITIMATE_BRANDS.keys())

        for legit in legit_domains:
            # Levenshtein distance for similarity
            similarity = difflib.SequenceMatcher(
                None, registrable_domain, legit
            ).ratio()

            # If 80%+ similar, likely typosquatting
            if 0.75 < similarity < 0.99:
                return {
                    "is_typo": True,
                    "similar_to": legit,
                    "similarity_score": similarity,
                    "score": 4
                }

            # Check for common character substitutions
            common_swaps = [
                ("0", "o"), ("1", "i"), ("1", "l"),
                ("5", "s"), ("3", "e"), ("7", "t")
            ]

            for char1, char2 in common_swaps:
                swapped = registrable_domain.replace(char1, char2)
                if swapped == legit:
                    return {
                        "is_typo": True,
                        "similar_to": legit,
                        "reason": f"Character substitution ({char1} -> {char2})",
                        "score": 5
                    }

        return {"is_typo": False}

    @staticmethod
    def _check_suspicious_keywords(url_path: str) -> int:
        """Score URL path/query for suspicious keywords"""

        score = 0
        url_lower = url_path.lower()

        for keyword, keyword_score in URLAnalyzer.SUSPICIOUS_KEYWORDS.items():
            if keyword in url_lower:
                score += keyword_score

        return score

    @staticmethod
    def _extract_tld(hostname: str) -> str:
        """Extract TLD from hostname"""
        parts = hostname.split(".")
        if len(parts) >= 2:
            return "." + parts[-1]
        return ""

    @staticmethod
    def _risk_level_from_score(score: int) -> str:
        """Convert score to risk level"""
        if score == 0:
            return "LOW"
        elif score <= 5:
            return "LOW"
        elif score <= 10:
            return "MEDIUM"
        elif score <= 15:
            return "HIGH"
        else:
            return "CRITICAL"
