"""
Agentic MX - URL Feature Extractor

IMPORTANT:
This file must remain compatible with the feature schema
used to train data/url_random_forest.pkl.

29 FEATURES:
1.  url_length
2.  hostname_length
3.  path_length
4.  query_length
5.  fragment_length
6.  num_dots
7.  num_hyphens
8.  num_digits
9.  num_special_chars
10. num_slashes
11. num_question_marks
12. num_equals
13. num_ampersands
14. num_percent_encoded
15. num_at_symbols
16. num_subdomains
17. hostname_entropy
18. path_entropy
19. has_ip
20. is_https
21. is_shortener
22. has_punycode
23. has_port
24. has_userinfo
25. suspicious_tld
26. suspicious_word_count
27. brand_word_count
28. long_url
29. very_long_url
"""

import math
import re
from urllib.parse import urlparse


# ============================================================
# EXACT TRAINING FEATURE ORDER
# ============================================================

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_ampersands",
    "num_percent_encoded",
    "num_at_symbols",
    "num_subdomains",
    "hostname_entropy",
    "path_entropy",
    "has_ip",
    "is_https",
    "is_shortener",
    "has_punycode",
    "has_port",
    "has_userinfo",
    "suspicious_tld",
    "suspicious_word_count",
    "brand_word_count",
    "long_url",
    "very_long_url",
]


SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "click",
    "link",
    "work",
    "zip",
    "mov",
    "icu",
    "cyou",
    "cam",
    "buzz",
    "live",
    "online",
    "site",
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rb.gy",
    "cutt.ly",
}


SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "credential",
    "bank",
    "banking",
    "payment",
    "invoice",
    "wallet",
    "crypto",
    "confirm",
    "authentication",
    "auth",
    "kyc",
    "otp",
    "refund",
    "bonus",
    "reward",
    "claim",
    "suspended",
    "unlock",
}


BRANDS = {
    "paypal",
    "microsoft",
    "google",
    "gmail",
    "amazon",
    "apple",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "sbi",
    "hdfc",
    "icici",
    "axis",
}


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text: str) -> float:

    if not text:
        return 0.0

    frequency = {}

    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    length = len(text)

    entropy = 0.0

    for count in frequency.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(url: str) -> dict:

    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        parse_url = "http://" + url
    else:
        parse_url = url

    try:

        parsed = urlparse(parse_url)

    except Exception:

        return _empty_features(url)


    hostname = (parsed.hostname or "").lower()

    path = parsed.path or ""

    query = parsed.query or ""

    fragment = parsed.fragment or ""


    features = {}


    # ========================================================
    # BASIC LENGTH FEATURES
    # ========================================================

    features["url_length"] = len(url)

    features["hostname_length"] = len(hostname)

    features["path_length"] = len(path)

    features["query_length"] = len(query)

    features["fragment_length"] = len(fragment)


    # ========================================================
    # CHARACTER FEATURES
    # ========================================================

    features["num_dots"] = url.count(".")

    features["num_hyphens"] = url.count("-")

    features["num_digits"] = sum(
        char.isdigit()
        for char in url
    )

    features["num_special_chars"] = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    features["num_slashes"] = url.count("/")

    features["num_question_marks"] = url.count("?")

    features["num_equals"] = url.count("=")

    features["num_ampersands"] = url.count("&")

    features["num_percent_encoded"] = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    features["num_at_symbols"] = url.count("@")


    # ========================================================
    # SUBDOMAINS
    # ========================================================

    hostname_parts = [
        part
        for part in hostname.split(".")
        if part
    ]

    if len(hostname_parts) >= 2:

        features["num_subdomains"] = max(
            0,
            len(hostname_parts) - 2
        )

    else:

        features["num_subdomains"] = 0


    # ========================================================
    # ENTROPY
    # ========================================================

    features["hostname_entropy"] = calculate_entropy(
        hostname
    )

    features["path_entropy"] = calculate_entropy(
        path
    )


    # ========================================================
    # IP ADDRESS
    # ========================================================

    ip_pattern = (
        r"^\d{1,3}\."
        r"\d{1,3}\."
        r"\d{1,3}\."
        r"\d{1,3}$"
    )

    features["has_ip"] = int(
        bool(
            re.match(
                ip_pattern,
                hostname
            )
        )
    )


    # ========================================================
    # HTTPS
    # ========================================================

    features["is_https"] = int(
        parsed.scheme.lower() == "https"
    )


    # ========================================================
    # SHORTENER
    # ========================================================

    features["is_shortener"] = int(
        hostname in SHORTENER_DOMAINS
    )


    # ========================================================
    # PUNYCODE
    # ========================================================

    features["has_punycode"] = int(
        "xn--" in hostname
    )


    # ========================================================
    # PORT
    # ========================================================

    try:

        features["has_port"] = int(
            parsed.port is not None
        )

    except ValueError:

        features["has_port"] = 1


    # ========================================================
    # USERINFO
    # ========================================================

    features["has_userinfo"] = int(
        "@" in parsed.netloc
    )


    # ========================================================
    # SUSPICIOUS TLD
    # ========================================================

    tld = ""

    if "." in hostname:

        tld = hostname.rsplit(
            ".",
            1
        )[-1].lower()

    features["suspicious_tld"] = int(
        tld in SUSPICIOUS_TLDS
    )


    # ========================================================
    # SUSPICIOUS WORDS
    # ========================================================

    lower_url = url.lower()

    suspicious_word_count = 0

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:

            suspicious_word_count += 1

    features["suspicious_word_count"] = (
        suspicious_word_count
    )


    # ========================================================
    # BRAND WORDS
    # ========================================================

    brand_word_count = 0

    for brand in BRANDS:

        if brand in lower_url:

            brand_word_count += 1

    features["brand_word_count"] = (
        brand_word_count
    )


    # ========================================================
    # URL LENGTH FLAGS
    # ========================================================

    features["long_url"] = int(
        len(url) > 75
    )

    features["very_long_url"] = int(
        len(url) > 150
    )


    # ========================================================
    # GUARANTEE EXACT FEATURE ORDER
    # ========================================================

    return {
        column: features.get(column, 0)
        for column in FEATURE_COLUMNS
    }


# ============================================================
# SAFE FALLBACK
# ============================================================

def _empty_features(url: str) -> dict:

    return {
        "url_length": len(url),
        "hostname_length": 0,
        "path_length": 0,
        "query_length": 0,
        "fragment_length": 0,
        "num_dots": 0,
        "num_hyphens": 0,
        "num_digits": 0,
        "num_special_chars": 0,
        "num_slashes": 0,
        "num_question_marks": 0,
        "num_equals": 0,
        "num_ampersands": 0,
        "num_percent_encoded": 0,
        "num_at_symbols": 0,
        "num_subdomains": 0,
        "hostname_entropy": 0.0,
        "path_entropy": 0.0,
        "has_ip": 0,
        "is_https": 0,
        "is_shortener": 0,
        "has_punycode": 0,
        "has_port": 0,
        "has_userinfo": 0,
        "suspicious_tld": 0,
        "suspicious_word_count": 0,
        "brand_word_count": 0,
        "long_url": int(len(url) > 75),
        "very_long_url": int(len(url) > 150),
    }


# ============================================================
# COMPATIBILITY ALIAS
# ============================================================

def get_features(url: str) -> dict:
    return extract_features(url)