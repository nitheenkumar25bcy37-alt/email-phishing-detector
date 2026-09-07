import re
import math
from urllib.parse import urlparse

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = "data/train.csv"
OUTPUT_FILE = "data/url_features_train.csv"


# ============================================================
# SUSPICIOUS / COMMON TLD LIST
# ============================================================

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


# ============================================================
# URL SHORTENERS
# ============================================================

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


# ============================================================
# SUSPICIOUS WORDS
# ============================================================

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


# ============================================================
# BRAND LIST
# ============================================================

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

def calculate_entropy(text):
    """
    Calculate Shannon entropy.

    Higher entropy can indicate randomly generated
    domains or paths.
    """

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
# DOMAIN EXTRACTION
# ============================================================

def get_registrable_domain(hostname):
    """
    Simple domain extraction.

    This intentionally avoids external network calls or
    third-party domain databases.
    """

    if not hostname:
        return ""

    parts = hostname.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    features = {}

    # --------------------------------------------------------
    # Basic cleanup
    # --------------------------------------------------------

    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        parse_url = "http://" + url
    else:
        parse_url = url

    try:
        parsed = urlparse(parse_url)

    except Exception:

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
            "label": 0,
        }

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # --------------------------------------------------------
    # Basic length features
    # --------------------------------------------------------

    features["url_length"] = len(url)

    features["hostname_length"] = len(hostname)

    features["path_length"] = len(path)

    features["query_length"] = len(query)

    features["fragment_length"] = len(fragment)

    # --------------------------------------------------------
    # Character features
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Subdomain
    # --------------------------------------------------------

    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 2:
        num_subdomains = max(
            0,
            len(hostname_parts) - 2
        )
    else:
        num_subdomains = 0

    features["num_subdomains"] = num_subdomains

    # --------------------------------------------------------
    # Entropy
    # --------------------------------------------------------

    features["hostname_entropy"] = calculate_entropy(
        hostname
    )

    features["path_entropy"] = calculate_entropy(
        path
    )

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    ip_pattern = (
        r"^\d{1,3}\."
        r"\d{1,3}\."
        r"\d{1,3}\."
        r"\d{1,3}$"
    )

    features["has_ip"] = int(
        bool(re.match(ip_pattern, hostname))
    )

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    features["is_https"] = int(
        parsed.scheme.lower() == "https"
    )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    features["is_shortener"] = int(
        hostname in SHORTENER_DOMAINS
    )

    # --------------------------------------------------------
    # Punycode
    # --------------------------------------------------------

    features["has_punycode"] = int(
        "xn--" in hostname
    )

    # --------------------------------------------------------
    # Port
    # --------------------------------------------------------

    try:
        port = parsed.port

        features["has_port"] = int(
            port is not None
        )

    except ValueError:

        features["has_port"] = 1

    # --------------------------------------------------------
    # Userinfo / @ trick
    # --------------------------------------------------------

    features["has_userinfo"] = int(
        "@" in parsed.netloc
    )

    # --------------------------------------------------------
    # TLD
    # --------------------------------------------------------

    if "." in hostname:

        tld = hostname.split(".")[-1]

    else:

        tld = ""

    features["suspicious_tld"] = int(
        tld in SUSPICIOUS_TLDS
    )

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    lower_url = url.lower()

    suspicious_word_count = 0

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:

            suspicious_word_count += 1

    features["suspicious_word_count"] = (
        suspicious_word_count
    )

    # --------------------------------------------------------
    # Brand words
    # --------------------------------------------------------

    brand_word_count = 0

    for brand in BRANDS:

        if brand in lower_url:

            brand_word_count += 1

    features["brand_word_count"] = (
        brand_word_count
    )

    # --------------------------------------------------------
    # URL length flags
    # --------------------------------------------------------

    features["long_url"] = int(
        len(url) > 75
    )

    features["very_long_url"] = int(
        len(url) > 150
    )

    return features


# ============================================================
# MAIN
# ============================================================

def main():

    print("============================================")
    print("URL FEATURE EXTRACTION")
    print("============================================")

    print("\nLoading training dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(
        f"URLs loaded: {len(df)}"
    )

    if "url" not in df.columns:
        raise ValueError(
            "Dataset must contain 'url' column."
        )

    if "label" not in df.columns:
        raise ValueError(
            "Dataset must contain 'label' column."
        )

    print("\nExtracting URL features...")

    feature_rows = []

    for index, row in df.iterrows():

        url = row["url"]

        features = extract_features(url)

        features["label"] = int(
            row["label"]
        )

        feature_rows.append(features)

        if (index + 1) % 5000 == 0:

            print(
                f"Processed "
                f"{index + 1}/{len(df)} URLs..."
            )

    feature_df = pd.DataFrame(
        feature_rows
    )

    # Put label first
    columns = [
        "label"
    ] + [
        column
        for column in feature_df.columns
        if column != "label"
    ]

    feature_df = feature_df[
        columns
    ]

    feature_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n============================================")
    print("FEATURE EXTRACTION COMPLETE")
    print("============================================")

    print(
        f"\nFeature dataset saved to:\n"
        f"{OUTPUT_FILE}"
    )

    print(
        f"\nNumber of samples: "
        f"{len(feature_df)}"
    )

    print(
        f"Number of features: "
        f"{len(feature_df.columns) - 1}"
    )

    print("\nFirst 5 rows:")

    print(
        feature_df.head().to_string(
            index=False
        )
    )


if __name__ == "__main__":
    main()