from backend.ml_classifier import MLClassifier
from backend.threat_scoring_engine import ThreatScoringEngine


def main():
    print("=" * 70)
    print("AGENTIC MX - COMPLETE THREAT SCORING TEST")
    print("=" * 70)

    test_url = "https://paypal-login-security.example.com/verify"

    print("\nTEST URL:")
    print(test_url)

    # ---------------------------------------------------------
    # 1. ML CLASSIFIER
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[1] ML CLASSIFIER")
    print("=" * 70)

    classifier = MLClassifier()

    ml_result = classifier.predict(test_url)

    print("Classification       :", ml_result.get("classification"))
    print("Phishing probability :", ml_result.get("phishing_probability"))
    print("Confidence           :", ml_result.get("confidence_score"))
    print("Model loaded         :", ml_result.get("model_loaded"))

    if ml_result.get("warning"):
        print("Warning              :", ml_result.get("warning"))

    # ---------------------------------------------------------
    # 2. URL INTELLIGENCE
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[2] URL INTELLIGENCE")
    print("=" * 70)

    try:
        from backend.url_analyzer import URLAnalyzer

        url_engine = URLAnalyzer()
        url_result = url_engine.analyze(test_url)

        print("Suspicious URLs      :",
              url_result.get("suspicious_urls_count", 0))

        extracted = url_result.get("extracted_urls", [])

        if extracted:
            first_url = extracted[0]

            print("Risk score            :",
                  first_url.get("risk_score"))

            print("Risk level            :",
                  first_url.get("risk_level"))

            print("Brand impersonation   :",
                  first_url.get("brand_impersonation"))

            print("Typosquatting         :",
                  first_url.get("typosquatting_detected"))

            print("Suspicious keywords   :",
                  first_url.get("suspicious_keywords"))

    except Exception as e:
        print("URL intelligence error:", e)

        # Safe fallback so scoring can still be tested
        url_result = {
            "suspicious_urls_count": 0,
            "brand_impersonations": [],
            "extracted_urls": []
        }

    # ---------------------------------------------------------
    # 3. NLP
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[3] NLP / SOCIAL ENGINEERING")
    print("=" * 70)

    # Temporary neutral result.
    # Replace this with your actual NLP engine once integrated.
    nlp_result = {
        "score": 0.0,
        "indicators": []
    }

    print("NLP score            :", nlp_result["score"])
    print("Indicators           :", nlp_result["indicators"])

    # ---------------------------------------------------------
    # 4. DOMAIN INTELLIGENCE
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[4] DOMAIN INTELLIGENCE")
    print("=" * 70)

    domain_result = {
        "mx_valid": None,
        "status": "unknown",
        "domain_age_days": None,
        "risk_flags": []
    }

    print("Domain intelligence  :", domain_result)

    # ---------------------------------------------------------
    # 5. AUTHENTICATION
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[5] EMAIL AUTHENTICATION")
    print("=" * 70)

    auth_result = {
        "spf_result": "NONE",
        "dmarc_result": "NONE",
        "from_reply_to_mismatch": False
    }

    print("Authentication       :", auth_result)

    # ---------------------------------------------------------
    # 6. ROUTING / INFRASTRUCTURE
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[6] INFRASTRUCTURE / ROUTING")
    print("=" * 70)

    routing_result = {
        "unusual_routing": False,
        "routing_anomalies": []
    }

    print("Routing intelligence :", routing_result)

    # ---------------------------------------------------------
    # 7. THREAT SCORING
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[7] THREAT SCORING ENGINE")
    print("=" * 70)

    engine = ThreatScoringEngine()

    try:
        # IMPORTANT:
        # Your class uses calculate_score(), NOT calculate()
        final_result = engine.calculate_score(
            ml_res=ml_result,
            nlp_res=nlp_result,
            url_res=url_result,
            domain_res=domain_result,
            auth_res=auth_result,
            routing_res=routing_result
        )

    except Exception as e:
        print("\n[SCORING ERROR]")
        print(e)
        return

    # ---------------------------------------------------------
    # 8. FINAL RESULT
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("[8] FINAL THREAT RESULT")
    print("=" * 70)

    print("\nFINAL SCORE:")
    print(final_result.score)

    print("\nRISK LEVEL:")
    print(final_result.risk_level)

    print("\nBREAKDOWN:")

    print("ML       :", final_result.breakdown.ml_score)
    print("NLP      :", final_result.breakdown.nlp_score)
    print("URL      :", final_result.breakdown.url_score)
    print("DOMAIN   :", final_result.breakdown.domain_score)
    print("AUTH     :", final_result.breakdown.auth_score)
    print("INFRA    :", final_result.breakdown.infra_score)

    print("\nEVIDENCE:")

    for evidence in final_result.evidence_factors:
        print("-", evidence)

    print("\n" + "=" * 70)
    print("COMPLETE TEST FINISHED")
    print("=" * 70)


if __name__ == "__main__":
    main()