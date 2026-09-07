#!/usr/bin/env python3
"""
NETRA-MAIL Test Suite
=====================

End-to-end API smoke/regression tests for the NETRA-MAIL phishing detector.

What this version fixes:
- No Unicode/emoji output, so Windows cp1252 terminals will not crash.
- Correct Python URL string.
- Uses the backend entry point documented by the project: backend.main:app
- Tests /health before email analysis.
- Uses stronger, clearly labeled phishing/legitimate scenarios.
- Uses classification-based acceptance criteria instead of fragile exact score bands.
- Saves a machine-readable test_results.json alongside the console output.
- Returns exit code 0 only when all scenarios pass.

IMPORTANT:
This is a prototype/regression test suite. Passing these five handcrafted
scenarios is NOT the same as proving 100% ML accuracy on a real dataset.
"""

import json
import sys
import time
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_BASE_URL = "http://localhost:8000"
ANALYZE_ENDPOINT = f"{API_BASE_URL}/api/v1/analyze/email"
HEALTH_ENDPOINT = f"{API_BASE_URL}/health"

TIMEOUT_SECONDS = 30
RESULTS_FILE = Path("test_results.json")


# ---------------------------------------------------------------------------
# Test payloads
# ---------------------------------------------------------------------------

TEST_EMAILS = [
    {
        "name": "Email 1 - Bank Phishing",
        "payload": {
            "subject": "URGENT: Bank Account Suspended - Verify Immediately",
            "sender": "security@bankofamerica-verify.com",
            "body": """
We detected suspicious activity on your bank account.

Your account has been temporarily locked because of multiple unauthorized
login attempts. You must verify your identity within 24 hours or your account
will be permanently disabled.

To restore access, provide your full name, email address, Social Security
Number, 16-digit card number, password and security information.

Failure to verify immediately may result in permanent account suspension.
""",
            "html": """
<html>
<body>
<h2>CRITICAL SECURITY ALERT</h2>
<p>Your account has been locked.</p>
<p>
<a href="https://bankofamerica-security-alerts.com/verify">
VERIFY YOUR ACCOUNT NOW
</a>
</p>
</body>
</html>
""",
        },
        "expected_class": "PHISHING",
        "minimum_score": 50,
    },
    {
        "name": "Email 2 - PayPal Phishing",
        "payload": {
            "subject": "Confirm Your PayPal Account - Action Required",
            "sender": "noreply@paypal-security-alert.com",
            "body": """
We detected unusual login activity on your PayPal account.

New device detected: iPhone 14 Pro
Location: Lagos, Nigeria
IP address: 196.223.15.78

For your security, verify your identity before accessing your account.

You must provide your PayPal email address, password, date of birth,
last four digits of your SSN, credit card number and CVV.

If you do not verify within 24 hours, your account will be suspended.
""",
            "html": """
<html>
<body>
<h2>PayPal Security Verification</h2>
<a href="https://paypal-verify-account.com/confirm">
CONFIRM MY ACCOUNT
</a>
</body>
</html>
""",
        },
        "expected_class": "PHISHING",
        "minimum_score": 50,
    },
    {
        "name": "Email 3 - CEO Fraud / Business Email Compromise",
        "payload": {
            "subject": "URGENT AND CONFIDENTIAL - Wire Transfer Required Today",
            "sender": "john.mitchell@companynamehere.com",
            "reply_to": "j.mitchell@ceo-private-email.com",
            "body": """
Hi Sarah,

I am currently in a confidential meeting and need your immediate assistance.

We have an urgent acquisition that must be finalized TODAY. Please wire
$185,000 to our new partner's account without notifying anyone else.

Bank Name: First International Banking Corp
Account Holder: David Chen
Account Number: 4782159630

DO NOT DISCUSS THIS WITH ANYONE ELSE.
I will handle all approvals directly.

Please also purchase $2,000 in Google Play cards for employee bonuses.

Time is critical. Confirm completion within the hour.

Thanks,
John Mitchell
CEO
""",
            "html": """
<html>
<body>
<h2>Urgent Confidential Wire Transfer</h2>
<p>Transfer $185,000 TODAY.</p>
<p>Do not notify anyone else.</p>
</body>
</html>
""",
        },
        "expected_class": "PHISHING",
        "minimum_score": 50,
    },
    {
        "name": "Email 4 - Microsoft Credential Phishing",
        "payload": {
            "subject": "Microsoft Account Security Alert - Verify Your Identity",
            "sender": "security-alerts@microsoft-account-verify.com",
            "body": """
Dear User,

We detected suspicious activity on your Microsoft account.

Login IP: 103.145.23.78
Location: Shanghai, China
Device: Unknown Android Phone

Your account has been temporarily locked.

Verify your Microsoft email address, password, phone number, date of birth,
credit/debit card information and security PIN immediately.

You have 24 hours to complete verification. Failure to do so will permanently
disable your account.
""",
            "html": """
<html>
<body>
<h2>Microsoft Account Security Alert</h2>
<p>
<a href="https://microsoft-account-verify-secure.com/security/verify">
VERIFY YOUR ACCOUNT
</a>
</p>
</body>
</html>
""",
        },
        "expected_class": "PHISHING",
        "minimum_score": 50,
    },
    {
        "name": "Email 5 - GitHub Legitimate",
        "payload": {
            "subject": "Welcome to GitHub - Verify Your Email Address",
            "sender": "support@github.com",
            "body": """
Thanks for signing up for GitHub. We're excited to have you on board.

To get started, please verify your email address.

Here's what you can do next:
- Set up your profile.
- Explore repositories.
- Create your first repository.
- Follow developers and organizations.

Questions? Please check the GitHub documentation.

Sincerely,
GitHub Account Team
""",
            "html": """
<html>
<body>
<h2>Welcome to GitHub!</h2>
<p>
<a href="https://github.com/email_verification">
Verify Email
</a>
</p>
</body>
</html>
""",
        },
        "expected_class": "SAFE",
        "maximum_score": 49,
    },
]


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def normalise(value) -> str:
    return str(value if value is not None else "").strip().upper()


def extract_result(data: dict) -> dict:
    """
    Supports both:
      {"decision": {...}, "netra_result": {...}}
    and responses where the result is directly available.
    """
    decision = data.get("decision") or {}
    netra_result = data.get("netra_result") or {}

    score = decision.get("score")
    if score is None:
        score = netra_result.get("score", data.get("score", 0))

    risk = decision.get("risk")
    if risk is None:
        risk = netra_result.get("risk", data.get("risk", "UNKNOWN"))

    action = decision.get("action")
    if action is None:
        action = netra_result.get("action", data.get("action", "REVIEW"))

    confidence = decision.get("confidence")
    if confidence is None:
        confidence = netra_result.get("confidence", data.get("confidence", 0))

    case_id = data.get("case_id")
    if case_id is None:
        case_id = netra_result.get("case_id", "N/A")

    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0

    return {
        "score": score,
        "risk": normalise(risk),
        "action": normalise(action),
        "confidence": confidence,
        "case_id": case_id,
    }


# ---------------------------------------------------------------------------
# Acceptance rules
# ---------------------------------------------------------------------------

def classification_ok(expected_class: str, risk: str, score: float) -> bool:
    """
    Classification acceptance is intentionally broader than the old fixed
    70-100/85-100 score windows.

    PHISHING:
      Accept HIGH or CRITICAL, or a score >= 50.

    SAFE:
      Accept SAFE, or a score < 50 when the engine does not expose SAFE.

    This tests the actual security decision rather than forcing one exact
    numeric score.
    """
    expected_class = normalise(expected_class)
    risk = normalise(risk)

    if expected_class == "PHISHING":
        return risk in {"HIGH", "CRITICAL", "PHISHING"} or score >= 50

    if expected_class == "SAFE":
        return risk in {"SAFE", "LEGITIMATE", "BENIGN"} or score < 50

    return False


def score_range_ok(test_case: dict, score: float) -> bool:
    """
    Only applies broad sanity bounds. We deliberately do not demand the old
    handcrafted ranges because score calibration can change as the detector
    evolves.
    """
    if not 0 <= score <= 100:
        return False

    if test_case["expected_class"] == "PHISHING":
        return score >= test_case.get("minimum_score", 0)

    return score <= test_case.get("maximum_score", 100)


# ---------------------------------------------------------------------------
# Backend checks
# ---------------------------------------------------------------------------

def test_health() -> bool:
    print_header("BACKEND HEALTH CHECK")

    try:
        response = requests.get(HEALTH_ENDPOINT, timeout=5)

        print(f"Endpoint: GET /health")
        print(f"HTTP status: {response.status_code}")

        if response.status_code != 200:
            print("FAIL: Backend health endpoint did not return HTTP 200.")
            print(f"Response: {response.text[:500]}")
            return False

        try:
            data = response.json()
        except ValueError:
            data = {}

        print("Backend status: HEALTHY")
        print(f"Version: {data.get('version', 'Unknown')}")
        print(f"Mode: {data.get('mode', 'Unknown')}")
        print(f"Model available: {data.get('model_available', 'Unknown')}")

        return True

    except requests.exceptions.ConnectionError:
        print("FAIL: Cannot connect to http://localhost:8000")
        print()
        print("Start the backend with:")
        print("python -m uvicorn backend.main:app --reload --port 8000")
        return False

    except requests.exceptions.Timeout:
        print("FAIL: Backend health request timed out.")
        return False

    except Exception as exc:
        print(f"FAIL: {exc}")
        return False


# ---------------------------------------------------------------------------
# Email tests
# ---------------------------------------------------------------------------

def test_email(test_case: dict) -> dict:
    name = test_case["name"]
    payload = test_case["payload"]
    expected = test_case["expected_class"]

    print(f"\nTesting: {name}")
    print(f"Expected classification: {expected}")
    print(f"Endpoint: POST /api/v1/analyze/email")

    started = time.perf_counter()

    result_record = {
        "name": name,
        "expected_class": expected,
        "passed": False,
        "http_status": None,
        "elapsed_seconds": None,
        "score": None,
        "risk": None,
        "action": None,
        "confidence": None,
        "case_id": None,
        "error": None,
    }

    try:
        response = requests.post(
            ANALYZE_ENDPOINT,
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )

        elapsed = time.perf_counter() - started
        result_record["http_status"] = response.status_code
        result_record["elapsed_seconds"] = round(elapsed, 3)

        if response.status_code != 200:
            result_record["error"] = (
                f"HTTP {response.status_code}: {response.text[:500]}"
            )
            print(f"FAIL: {result_record['error']}")
            return result_record

        try:
            data = response.json()
        except ValueError:
            result_record["error"] = "Backend returned non-JSON response."
            print(f"FAIL: {result_record['error']}")
            return result_record

        extracted = extract_result(data)
        result_record.update(extracted)

        score = extracted["score"]
        risk = extracted["risk"]

        class_ok = classification_ok(expected, risk, score)
        score_ok = score_range_ok(test_case, score)

        # HTTP + classification + broad score sanity are all required.
        passed = class_ok and score_ok
        result_record["passed"] = passed

        print(f"HTTP status: {response.status_code}")
        print(f"Response time: {elapsed:.2f}s")
        print(f"Case ID: {extracted['case_id']}")
        print(f"Risk score: {score:.1f}/100")
        print(f"Risk level: {risk}")
        print(f"Recommended action: {extracted['action']}")
        print(f"Confidence: {extracted['confidence']}")
        print(f"Classification check: {'PASS' if class_ok else 'FAIL'}")
        print(f"Score sanity check: {'PASS' if score_ok else 'FAIL'}")
        print(f"RESULT: {'PASS' if passed else 'FAIL'}")

        if not passed:
            if not class_ok:
                print(
                    f"Reason: expected {expected}, received risk={risk}, "
                    f"score={score:.1f}"
                )
            if not score_ok:
                print(
                    f"Reason: score did not satisfy the broad threshold "
                    f"for {expected}"
                )

        return result_record

    except requests.exceptions.ConnectionError:
        result_record["error"] = "Cannot connect to backend."
        print("FAIL: Cannot connect to http://localhost:8000")
        return result_record

    except requests.exceptions.Timeout:
        result_record["error"] = "Request timed out."
        print("FAIL: Request timed out.")
        return result_record

    except Exception as exc:
        result_record["error"] = str(exc)
        print(f"FAIL: {exc}")
        return result_record


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_tests() -> int:
    print_header("NETRA-MAIL PHISHING DETECTION - AUTOMATED TEST SUITE")

    print(f"Backend: {API_BASE_URL}")
    print(f"Scenarios: {len(TEST_EMAILS)}")

    if not test_health():
        print_header("TEST SUITE STOPPED")
        print("Backend health check failed.")
        return 1

    print_header("RUNNING EMAIL ANALYSIS TESTS")

    results = []

    for test_case in TEST_EMAILS:
        results.append(test_email(test_case))
        time.sleep(0.5)

    passed = sum(1 for result in results if result["passed"])
    total = len(results)

    # Save structured output for calculate_metrics.py.
    output = {
        "project": "NETRA-MAIL",
        "backend": API_BASE_URL,
        "total_tests": total,
        "passed_tests": passed,
        "failed_tests": total - passed,
        "prototype_pass_rate": round((passed / total) * 100, 2) if total else 0,
        "tests": results,
        "generated_at_epoch": time.time(),
    }

    RESULTS_FILE.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )

    print_header("TEST SUMMARY")

    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"[{status}] {result['name']}")

    print()
    print(f"Prototype scenarios passed: {passed}/{total}")
    print(f"Prototype scenario pass rate: {output['prototype_pass_rate']:.2f}%")
    print(f"Structured results saved to: {RESULTS_FILE}")

    print()
    print("IMPORTANT:")
    print(
        "This five-case pass rate is an end-to-end prototype/regression "
        "metric, not a statistically valid ML accuracy benchmark."
    )

    if passed == total:
        print()
        print("ALL PROTOTYPE SCENARIOS PASSED.")
        return 0

    print()
    print("SOME PROTOTYPE SCENARIOS FAILED.")
    print("Review the individual results above.")
    return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
