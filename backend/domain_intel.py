import re
import socket
from urllib.parse import urlparse
from typing import Dict, Any, List


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein edit distance.
    """

    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1, start=1):
        current_row = [i]

        for j, c2 in enumerate(s2, start=1):
            insertions = current_row[j - 1] + 1
            deletions = previous_row[j] + 1
            substitutions = previous_row[j - 1] + (c1 != c2)

            current_row.append(
                min(insertions, deletions, substitutions)
            )

        previous_row = current_row

    return previous_row[-1]


class DomainForensics:
    """
    Sender/domain intelligence engine.

    Unlike the older implementation, this module analyzes:

        - From domain
        - Reply-To domain
        - Return-Path domain
        - URL domains
        - Received infrastructure domains
        - Brand impersonation
        - Typosquatting
        - Punycode
        - Suspicious TLDs
        - DNS resolution

    It performs static analysis only.
    """

    BRANDS = {
        "paypal": ["paypal.com"],
        "microsoft": [
            "microsoft.com",
            "live.com",
            "office.com",
            "office365.com",
        ],
        "google": [
            "google.com",
            "gmail.com",
        ],
        "amazon": ["amazon.com"],
        "apple": [
            "apple.com",
            "icloud.com",
        ],
        "netflix": ["netflix.com"],
        "facebook": [
            "facebook.com",
            "meta.com",
        ],
        "instagram": ["instagram.com"],
        "linkedin": ["linkedin.com"],
        "github": ["github.com"],
        "sbi": ["sbi.co.in"],
        "hdfcbank": ["hdfcbank.com"],
        "icicibank": ["icicibank.com"],
        "axisbank": ["axisbank.com"],
        "uidai": ["uidai.gov.in"],
        "incometax": ["incometax.gov.in"],
    }

    SUSPICIOUS_TLDS = {
        ".xyz",
        ".top",
        ".work",
        ".click",
        ".buzz",
        ".cam",
        ".rest",
        ".tk",
        ".ml",
        ".ga",
        ".gq",
        ".cf",
    }

    # Words commonly inserted into impersonation domains.
    IMPERSONATION_TERMS = {
        "update",
        "updates",
        "secure",
        "security",
        "verify",
        "verification",
        "login",
        "signin",
        "support",
        "service",
        "services",
        "account",
        "accounts",
        "alert",
        "alerts",
        "notification",
        "billing",
        "payment",
        "confirm",
        "confirmation",
        "help",
        "official",
        "customer",
    }

    @classmethod
    def _normalize_domain(cls, domain: str) -> str:
        if not domain:
            return ""

        domain = str(domain).strip().lower()

        # Remove email address if a complete address was passed.
        if "@" in domain:
            domain = domain.rsplit("@", 1)[-1]

        # Remove URL scheme/path if present.
        try:
            if "://" in domain:
                parsed = urlparse(domain)
                domain = parsed.hostname or ""
            else:
                parsed = urlparse("//" + domain)
                domain = parsed.hostname or domain
        except Exception:
            pass

        domain = domain.strip().strip(".")

        # Remove accidental port.
        domain = domain.split(":")[0]

        return domain

    @classmethod
    def _base_label(cls, domain: str) -> str:
        domain = cls._normalize_domain(domain)

        if not domain:
            return ""

        labels = domain.split(".")

        if len(labels) >= 2:
            return labels[-2]

        return labels[0]

    @classmethod
    def _registered_domain(cls, domain: str) -> str:
        """
        Lightweight registered-domain approximation.

        This intentionally avoids external dependencies.
        """
        domain = cls._normalize_domain(domain)

        if not domain:
            return ""

        labels = domain.split(".")

        if len(labels) >= 2:
            return ".".join(labels[-2:])

        return domain

    @classmethod
    def _is_legitimate_for_brand(
        cls,
        domain: str,
        legitimate_domains: List[str],
    ) -> bool:
        domain = cls._normalize_domain(domain)

        for legitimate in legitimate_domains:
            legitimate = cls._normalize_domain(legitimate)

            if (
                domain == legitimate
                or domain.endswith("." + legitimate)
            ):
                return True

        return False

    @classmethod
    def detect_brand_impersonation(
        cls,
        domain: str,
    ) -> List[str]:
        """
        Detect brand names appearing inside a domain that is
        NOT the legitimate brand infrastructure.

        Example:

            paypal.com
                -> legitimate

            paypal-update.com
                -> PayPal impersonation

            secure-paypal-login.com
                -> PayPal impersonation
        """

        domain = cls._normalize_domain(domain)

        if not domain:
            return []

        labels = domain.split(".")
        base_label = cls._base_label(domain)

        results = []

        for brand, legitimate_domains in cls.BRANDS.items():

            if cls._is_legitimate_for_brand(
                domain,
                legitimate_domains,
            ):
                continue

            # Brand appears directly or as part of a label.
            brand_present = (
                brand in base_label
                or any(
                    brand == label
                    or brand in label
                    for label in labels
                )
            )

            if brand_present:
                results.append(brand.title())

        return sorted(set(results))

    @classmethod
    def detect_typosquatting(
        cls,
        domain: str,
    ) -> List[Dict[str, Any]]:
        """
        Detect close edit-distance domain impersonation.
        """

        domain = cls._normalize_domain(domain)

        if not domain:
            return []

        base_label = cls._base_label(domain)

        results = []

        for brand, legitimate_domains in cls.BRANDS.items():

            if cls._is_legitimate_for_brand(
                domain,
                legitimate_domains,
            ):
                continue

            distance = levenshtein_distance(
                base_label,
                brand,
            )

            if (
                distance > 0
                and distance <= 2
                and len(base_label) >= 4
            ):
                results.append(
                    {
                        "brand": brand.title(),
                        "distance": distance,
                        "legitimate_domains": legitimate_domains,
                    }
                )

        return results

    @classmethod
    def analyze_domain(
        cls,
        domain: str,
        source: str = "unknown",
    ) -> Dict[str, Any]:
        """
        Analyze a single domain.
        """

        domain_clean = cls._normalize_domain(domain)

        if not domain_clean:
            return {
                "domain": "",
                "source": source,
                "valid": False,
                "risk_score": 0,
                "risk_level": "LOW",
                "impersonated_brands": [],
                "typosquatting": [],
                "reasons": [],
                "resolves": False,
                "resolved_ip": None,
                "is_punycode": False,
                "has_suspicious_tld": False,
                "registered_domain": "",
            }

        is_punycode = "xn--" in domain_clean

        has_suspicious_tld = any(
            domain_clean.endswith(tld)
            for tld in cls.SUSPICIOUS_TLDS
        )

        brand_impersonation = (
            cls.detect_brand_impersonation(domain_clean)
        )

        typosquatting = (
            cls.detect_typosquatting(domain_clean)
        )

        resolves = False
        resolved_ip = None

        try:
            resolved_ip = socket.gethostbyname(domain_clean)
            resolves = True
        except Exception:
            resolves = False

        risk_score = 0
        reasons = []

        if is_punycode:
            risk_score += 35
            reasons.append(
                "Punycode/homoglyph-style domain detected."
            )

        if has_suspicious_tld:
            risk_score += 25
            reasons.append(
                "Domain uses a TLD frequently associated with abuse."
            )

        if brand_impersonation:
            risk_score += min(
                50,
                35 + (len(brand_impersonation) - 1) * 10,
            )

            for brand in brand_impersonation:
                reasons.append(
                    f"Domain appears to impersonate {brand}."
                )

        for typo in typosquatting:
            risk_score += 30
            reasons.append(
                f"Domain closely resembles legitimate "
                f"{typo['brand']} infrastructure "
                f"(edit distance {typo['distance']})."
            )

        # Brand-looking domain with an added modifier such as
        # paypal-update.com is suspicious even though it is not
        # a traditional one-character typo.
        base_label = cls._base_label(domain_clean)

        for brand in cls.BRANDS:
            if (
                brand in base_label
                and base_label != brand
                and brand.title() not in brand_impersonation
            ):
                risk_score += 30
                reasons.append(
                    f"Domain contains the protected brand name "
                    f"{brand.title()} in a non-legitimate domain."
                )

        if not resolves:
            risk_score += 5
            reasons.append(
                "Domain did not resolve through standard DNS."
            )

        risk_score = min(100, max(0, risk_score))

        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "domain": domain_clean,
            "source": source,
            "valid": True,
            "registered_domain": cls._registered_domain(
                domain_clean
            ),
            "is_punycode": is_punycode,
            "has_suspicious_tld": has_suspicious_tld,
            "impersonated_brands": brand_impersonation,
            "impersonated_brand": (
                brand_impersonation[0]
                if brand_impersonation
                else None
            ),
            "typosquatting": typosquatting,
            "resolves": resolves,
            "resolved_ip": resolved_ip,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
        }

    @classmethod
    def inspect_domains(
        cls,
        domains: List[str],
    ) -> Dict[str, Any]:
        """
        Analyze multiple domains.
        """

        results = []

        seen = set()

        for item in domains or []:

            if not item:
                continue

            if isinstance(item, dict):
                domain = item.get("domain", "")
                source = item.get("source", "unknown")
            else:
                domain = str(item)
                source = "unknown"

            normalized = cls._normalize_domain(domain)

            if not normalized or normalized in seen:
                continue

            seen.add(normalized)

            result = cls.analyze_domain(
                normalized,
                source=source,
            )

            results.append(result)

        highest = max(
            (
                item.get("risk_score", 0)
                for item in results
            ),
            default=0,
        )

        brands = sorted(
            {
                brand
                for item in results
                for brand in item.get(
                    "impersonated_brands",
                    [],
                )
            }
        )

        typos = [
            typo
            for item in results
            for typo in item.get(
                "typosquatting",
                [],
            )
        ]

        reasons = []
        for item in results:
            reasons.extend(
                item.get("reasons", [])
            )

        if highest >= 70:
            overall_risk = "CRITICAL"
        elif highest >= 50:
            overall_risk = "HIGH"
        elif highest >= 30:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        return {
            "total_domains": len(results),
            "highest_risk_score": highest,
            "overall_risk": overall_risk,
            "impersonated_brands": brands,
            "typosquatting_detected": typos,
            "reasons": list(dict.fromkeys(reasons)),
            "domains": results,
        }

    @classmethod
    def inspect_urls(
        cls,
        urls: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Backward-compatible URL inspection.

        Existing code may call this method.
        """

        results = []

        for url in urls or []:

            try:
                parsed = urlparse(str(url))

                hostname = (
                    parsed.hostname
                    or ""
                ).lower()

                if not hostname:
                    continue

                domain_meta = cls.analyze_domain(
                    hostname,
                    source="url",
                )

                # Raw IP URLs are high-risk.
                if re.fullmatch(
                    r"\d{1,3}(?:\.\d{1,3}){3}",
                    hostname,
                ):
                    domain_meta["risk_score"] = max(
                        domain_meta["risk_score"],
                        80,
                    )
                    domain_meta["risk_level"] = "CRITICAL"
                    domain_meta["reasons"].append(
                        "URL uses a raw IP address instead of a domain."
                    )

                results.append(
                    {
                        "url": str(url),
                        "domain": hostname,
                        "path": parsed.path,
                        "analysis": domain_meta,
                    }
                )

            except Exception:
                continue

        return results