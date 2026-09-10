import json
import sys
from pathlib import Path
import requests

BASE_URL = "http://127.0.0.1:8000"
ENDPOINT = f"{BASE_URL}/api/v1/analyze/eml"
ROOT = Path(__file__).resolve().parent
EMAIL_DIR = ROOT / "emails"
MANIFEST_FILE = EMAIL_DIR / "MANIFEST.json"
RESULTS_FILE = ROOT / "results.json"

# These are evaluation expectations, not production policy.
# A "signal" means the detector produced LOW/HIGH/CRITICAL or REVIEW/
# QUARANTINE/BLOCK. Legitimate and authentication-unavailable samples should
# remain SAFE/ALLOW. Reply-To mismatch and malformed-like samples are expected
# to surface as review/low-risk signals, not necessarily malicious verdicts.
EXPECTED = {
    "01_legitimate_meeting.eml": {"class": "legitimate", "threat": False},
    "02_legitimate_business.eml": {"class": "legitimate", "threat": False},
    "03_credential_phishing.eml": {"class": "credential_phishing", "threat": True},
    "04_urgent_phishing.eml": {"class": "urgent_phishing", "threat": True},
    "05_bec_payment.eml": {"class": "bec", "threat": True},
    "06_suspicious_url.eml": {"class": "suspicious_url", "threat": True},
    "07_ssrf_localhost.eml": {"class": "ssrf", "threat": True},
    "08_executable_attachment.eml": {"class": "executable_attachment", "threat": True},
    "09_double_extension.eml": {"class": "double_extension", "threat": True},
    "10_macro_document.eml": {"class": "macro_document", "threat": True},
    "11_html_attachment.eml": {"class": "html_attachment", "threat": True},
    "12_svg_attachment.eml": {"class": "svg_attachment", "threat": True},
    "13_suspicious_archive.eml": {"class": "archive", "threat": True},
    "14_mime_mismatch.eml": {"class": "mime_mismatch", "threat": True},
    "15_punycode_url.eml": {"class": "punycode_url", "threat": True},
    "16_raw_ip_url.eml": {"class": "raw_ip_url", "threat": True},
    "17_reply_to_mismatch.eml": {"class": "reply_to_mismatch", "threat": True},
    "18_mixed_attack.eml": {"class": "mixed_attack", "threat": True},
    "19_malformed_like.eml": {"class": "parser_robustness", "threat": False, "robustness": True},
    "20_authentication_unavailable.eml": {"class": "auth_unavailable", "threat": False},
}


def load_manifest():
    if not MANIFEST_FILE.exists():
        return {}
    try:
        data = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {str(x.get("file")): x for x in data if isinstance(x, dict) and x.get("file")}
        if isinstance(data, dict):
            return data
    except Exception as exc:
        print(f"WARNING: Could not read MANIFEST.json: {type(exc).__name__}: {exc}")
    return {}


def analyze_email(path):
    try:
        with path.open("rb") as f:
            response = requests.post(
                ENDPOINT,
                files={"file": (path.name, f, "message/rfc822")},
                timeout=60,
            )
        try:
            data = response.json()
        except Exception:
            data = {"raw_response": response.text}
        return response.status_code, data, None
    except Exception as exc:
        return None, {}, f"{type(exc).__name__}: {exc}"


def classify_detection(file_name, decision):
    expected = EXPECTED.get(file_name, {"threat": False})
    risk = str(decision.get("risk") or "").upper()
    action = str(decision.get("action") or "").upper()
    observed_signal = risk not in {"", "SAFE"} or action in {"REVIEW", "QUARANTINE", "BLOCK"}
    expected_signal = bool(expected.get("threat"))
    return observed_signal, expected_signal


def main():
    if not EMAIL_DIR.exists():
        print(f"ERROR: Email directory not found: {EMAIL_DIR}")
        sys.exit(1)

    files = sorted(EMAIL_DIR.glob("*.eml"))
    if not files:
        print(f"ERROR: No .eml files found in {EMAIL_DIR}")
        sys.exit(1)

    manifest = load_manifest()
    print("=" * 75)
    print("NETRA DETERMINISTIC EMAIL EVALUATION")
    print("=" * 75)
    print(f"Endpoint : {ENDPOINT}")
    print(f"Test files: {len(files)}")
    print()

    results = []
    for index, path in enumerate(files, 1):
        print(f"[{index:02d}/{len(files):02d}] {path.name}")
        status_code, data, error = analyze_email(path)

        decision = data.get("decision", {}) if isinstance(data, dict) else {}
        threat = data.get("threat_score", {}) if isinstance(data, dict) else {}
        report = data.get("report", {}) if isinstance(data, dict) else {}
        report_threat = report.get("threat_score", {}) if isinstance(report, dict) else {}
        netra = data.get("netra_result", {}) if isinstance(data, dict) else {}
        attachment = data.get("attachment_analysis", {}) if isinstance(data, dict) else {}
        url_intel = data.get("url_intelligence", {}) if isinstance(data, dict) else {}
        summary = url_intel.get("summary", {}) if isinstance(url_intel, dict) else {}

        observed_signal, expected_signal = classify_detection(path.name, decision)
        passed = observed_signal == expected_signal and status_code == 200 and not error

        result = {
            "file": path.name,
            "class": EXPECTED.get(path.name, {}).get("class", manifest.get(path.name, {}).get("category", "unknown")),
            "expected_threat_signal": expected_signal,
            "observed_threat_signal": observed_signal,
            "passed": passed,
            "http_status": status_code,
            "api_status": data.get("status") if isinstance(data, dict) else None,
            "case_id": data.get("case_id") if isinstance(data, dict) else None,
            "risk": decision.get("risk"),
            "score": decision.get("score"),
            "action": decision.get("action"),
            "confidence": decision.get("confidence"),
            "attack_classification": decision.get("attack_classification", []),
            "reasons": decision.get("reasons", []),
            "report_score": report_threat.get("score"),
            "report_risk": report_threat.get("risk_level"),
            "top_level_score": threat.get("score"),
            "netra_score": netra.get("score"),
            "netra_risk": netra.get("risk"),
            "netra_action": netra.get("action"),
            "attachment_score": attachment.get("score", 0),
            "attachment_risk": attachment.get("risk_level"),
            "url_score": summary.get("highest_url_score", 0),
            "error": error,
        }
        results.append(result)

        if error:
            print(f"      ERROR | {error}")
        elif status_code != 200:
            print(f"      HTTP {status_code} | FAIL")
        else:
            print(f"      {str(decision.get('risk', 'UNKNOWN')):8} | score={decision.get('score', '?')} | {decision.get('action', 'UNKNOWN')} | {'PASS' if passed else 'CHECK'}")

    RESULTS_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")

    evaluated = [r for r in results if r["file"] in EXPECTED]
    threat_cases = [r for r in evaluated if r["expected_threat_signal"]]
    benign_cases = [r for r in evaluated if not r["expected_threat_signal"] and not EXPECTED[r["file"]].get("robustness")]
    robustness_cases = [r for r in evaluated if EXPECTED[r["file"]].get("robustness")]

    tp = sum(r["observed_threat_signal"] for r in threat_cases)
    fn = len(threat_cases) - tp
    fp = sum(r["observed_threat_signal"] for r in benign_cases)
    tn = len(benign_cases) - fp
    detection_rate = (tp / len(threat_cases) * 100) if threat_cases else 0.0
    false_positive_rate = (fp / len(benign_cases) * 100) if benign_cases else 0.0
    passed = sum(r["passed"] for r in evaluated)

    consistency_cases = [
        r for r in results
        if r["http_status"] == 200
        and r["report_score"] is not None
        and r["top_level_score"] is not None
        and r["netra_score"] is not None
    ]
    consistency_pass = sum(
        r["report_score"] == r["top_level_score"] == r["netra_score"]
        for r in consistency_cases
    )

    print()
    print("=" * 75)
    print("EVALUATION SUMMARY")
    print("=" * 75)
    print(f"Cases evaluated       : {len(evaluated)}")
    print(f"Threat cases          : {len(threat_cases)}")
    print(f"Threats detected      : {tp}/{len(threat_cases)} ({detection_rate:.1f}%)")
    print(f"False positives       : {fp}/{len(benign_cases)} ({false_positive_rate:.1f}%)")
    print(f"TP / FN / FP / TN     : {tp} / {fn} / {fp} / {tn}")
    print(f"Case expectation pass : {passed}/{len(evaluated)} ({passed / len(evaluated) * 100:.1f}%)" if evaluated else "Case expectation pass : 0/0")
    print(f"Verdict consistency   : {consistency_pass}/{len(consistency_cases)}" if consistency_cases else "Verdict consistency   : 0/0")
    print(f"Robustness test       : {robustness_cases[0]['risk']} / {robustness_cases[0]['action']}" if robustness_cases else "Robustness test       : not evaluated")
    print()

    failures = [r for r in evaluated if not r["passed"]]
    if failures:
        print("Cases needing review:")
        for r in failures:
            print(f"  - {r['file']}: expected_signal={r['expected_threat_signal']} observed_signal={r['observed_threat_signal']} risk={r['risk']} score={r['score']} action={r['action']}")
    else:
        print("All deterministic expectation checks passed.")

    print()
    print(f"Results saved to: {RESULTS_FILE}")
    print("=" * 75)


if __name__ == "__main__":
    main()
