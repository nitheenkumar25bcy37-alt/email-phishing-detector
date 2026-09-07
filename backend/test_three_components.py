"""
Agentic MX
Three Component Integration Test

Tests:

1. URL feature extractor
2. Random Forest ML classifier
3. URL intelligence
4. Threat scoring engine
"""

from backend.url_feature_extractor import (
    extract_features,
    FEATURE_COLUMNS,
)

from backend.ml_classifier import (
    MLClassifier,
)

from backend.url_analyzer import (
    URLAnalyzer,
)

from backend.threat_scoring_engine import (
    ThreatScoringEngine,
)


def main():

    print("=" * 70)
    print("AGENTIC MX - THREE COMPONENT INTEGRATION TEST")
    print("=" * 70)


    # ========================================================
    # TEST URL
    # ========================================================

    url = (
        "https://paypal-login-security.example.com/"
        "verify"
    )


    # ========================================================
    # 1. FEATURE EXTRACTION
    # ========================================================

    print("\n[1] FEATURE EXTRACTOR")
    print("-" * 70)


    features = extract_features(
        url
    )


    print(
        "Feature count:",
        len(features)
    )


    print(
        "Expected:",
        len(FEATURE_COLUMNS)
    )


    missing = [
        column
        for column in FEATURE_COLUMNS
        if column not in features
    ]


    if missing:

        print(
            "ERROR: Missing features:",
            missing
        )

        return


    print(
        "Feature verification: PASSED"
    )


    # ========================================================
    # 2. ML CLASSIFIER
    # ========================================================

    print("\n[2] RANDOM FOREST ML")
    print("-" * 70)


    classifier = MLClassifier()


    print(
        "Model loaded:",
        classifier.model_loaded
    )


    print(
        "Model path:",
        classifier.model_path
    )


    print(
        "Error:",
        classifier.error
    )


    if not classifier.model_loaded:

        print(
            "\nERROR: Random Forest failed to load."
        )

        return


    ml_result = classifier.predict(
        url
    )


    print(
        "Classification:",
        ml_result["classification"]
    )


    print(
        "Phishing probability:",
        ml_result["phishing_probability"]
    )


    print(
        "Confidence:",
        ml_result["confidence_score"]
    )


    print(
        "Threshold:",
        ml_result["threshold"]
    )


    # ========================================================
    # 3. URL INTELLIGENCE
    # ========================================================

    print("\n[3] URL INTELLIGENCE")
    print("-" * 70)


    analyzer = URLAnalyzer()


    url_result = analyzer.analyze(
        url
    )


    print(
        "Total URLs:",
        url_result["total_urls"]
    )


    print(
        "Suspicious URLs:",
        url_result[
            "suspicious_urls_count"
        ]
    )


    print(
        "Brand impersonations:",
        url_result[
            "brand_impersonations"
        ]
    )


    for finding in url_result[
        "extracted_urls"
    ]:

        print(
            "\nURL:",
            finding["url"]
        )

        print(
            "Risk score:",
            finding["risk_score"]
        )

        print(
            "Risk level:",
            finding["risk_level"]
        )

        print(
            "Keywords:",
            finding[
                "suspicious_keywords"
            ]
        )


    # ========================================================
    # 4. THREAT SCORING
    # ========================================================

    print("\n[4] THREAT SCORING ENGINE")
    print("-" * 70)


    engine = ThreatScoringEngine()


    nlp_result = {
        "score": 0.0,
        "indicators": [],
    }


    domain_result = {
        "mx_valid": None,
        "status": "unknown",
        "domain_age_days": None,
        "risk_flags": [],
    }


    auth_result = {
        "spf_result": "NONE",
        "dmarc_result": "NONE",
        "from_reply_to_mismatch": False,
    }


    routing_result = {
        "unusual_routing": False,
        "routing_anomalies": [],
    }


    final_result = engine.calculate_score(

        ml_res=ml_result,

        nlp_res=nlp_result,

        url_res=url_result,

        domain_res=domain_result,

        auth_res=auth_result,

        routing_res=routing_result,
    )


    # ========================================================
    # FINAL
    # ========================================================

    print("\n" + "=" * 70)
    print("FINAL RESULT")
    print("=" * 70)


    print(
        "\nSCORE:",
        final_result.score
    )


    print(
        "RISK LEVEL:",
        final_result.risk_level
    )


    print(
        "\nBREAKDOWN:"
    )


    print(
        "ML:",
        final_result.breakdown.ml_score
    )


    print(
        "NLP:",
        final_result.breakdown.nlp_score
    )


    print(
        "URL:",
        final_result.breakdown.url_score
    )


    print(
        "DOMAIN:",
        final_result.breakdown.domain_score
    )


    print(
        "AUTH:",
        final_result.breakdown.auth_score
    )


    print(
        "INFRA:",
        final_result.breakdown.infra_score
    )


    print(
        "\nEVIDENCE:"
    )


    for item in (
        final_result.evidence_factors
    ):

        print(
            "-",
            item
        )


    print("\n" + "=" * 70)
    print("THREE COMPONENT TEST PASSED")
    print("=" * 70)


if __name__ == "__main__":

    main()