"""
NETRA-Mail 7.10 — Final Integration & Regression Suite

Run from the PROJECT ROOT:
    python evaluation/run_7_10_regression.py

This suite is intentionally non-destructive. It uses FastAPI TestClient and
creates/updates only normal test records in the configured local forensic DB.
It does not change detector thresholds or production source files.

Checks:
  1. Import / application boot
  2. Route registration / OpenAPI
  3. Health + readiness
  4. V1 direct email compatibility
  5. V1 EML upload
  6. V1 forensic case retrieval + audit
  7. V2 text analysis
  8. V2 EML upload + evidence registration
  9. V2 email retrieval/findings/trace/graph/relationships
 10. Campaign lifecycle
 11. Case lifecycle
 12. Case-email/campaign/note/tag/timeline workflow
 13. Evidence verify/version/custody workflow
 14. Case evidence + custody
 15. JSON report generation + retrieval + download
 16. Dashboard/listing
 17. IP/domain intelligence endpoints
 18. Input validation / expected 4xx
 19. SSRF safety smoke test
 20. Deterministic 20-case regression, if the corpus is present
 21. Final ledger integrity

The script treats the malformed-like deterministic sample as a ROBUSTNESS
case, not as a false positive, because LOW/REVIEW is an acceptable safe
handling outcome for malformed input.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from fastapi.testclient import TestClient
except Exception as exc:
    print(f"[FATAL] FastAPI TestClient unavailable: {type(exc).__name__}: {exc}")
    sys.exit(2)

try:
    from backend.main import app
except Exception as exc:
    print(f"[FATAL] backend.main failed to import: {type(exc).__name__}: {exc}")
    print("        Run this script from the project root and verify dependencies.")
    sys.exit(2)

PASS = 0
FAIL = 0
WARN = 0
RESULTS: list[dict[str, Any]] = []


def record(name: str, ok: bool, detail: str = "", warning: bool = False) -> None:
    global PASS, FAIL, WARN
    if ok:
        PASS += 1
        state = "PASS"
    elif warning:
        WARN += 1
        state = "WARN"
    else:
        FAIL += 1
        state = "FAIL"

    RESULTS.append({"name": name, "status": state, "detail": detail})
    print(f"[{state:<4}] {name}" + (f" — {detail}" if detail else ""))


def json_body(response) -> dict[str, Any]:
    try:
        value = response.json()
        return value if isinstance(value, dict) else {"_value": value}
    except Exception:
        return {}


def request_json(client, method: str, path: str, **kwargs):
    try:
        return client.request(method, path, **kwargs)
    except Exception as exc:
        record(f"{method} {path}", False, f"client exception: {type(exc).__name__}: {exc}")
        return None


def expect_status(
    name: str,
    response,
    allowed: set[int] | tuple[int, ...],
    detail: str = "",
) -> bool:
    if response is None:
        record(name, False, "no response")
        return False
    ok = response.status_code in set(allowed)
    body = ""
    if not ok:
        try:
            body = json.dumps(response.json(), ensure_ascii=False)[:500]
        except Exception:
            body = response.text[:500]
    record(
        name,
        ok,
        detail or (f"HTTP {response.status_code}" + (f" body={body}" if body else "")),
    )
    return ok


def load_corpus() -> dict[str, bytes]:
    candidates = [
        ROOT / "evaluation" / "deterministic" / "deterministic_email_test_corpus.zip",
        ROOT / "deterministic_email_test_corpus.zip",
    ]
    for path in candidates:
        if path.is_file():
            with zipfile.ZipFile(path, "r") as zf:
                return {
                    name: zf.read(name)
                    for name in zf.namelist()
                    if name.lower().endswith(".eml")
                }
    return {}


def main() -> int:
    print("=" * 72)
    print("NETRA-Mail 7.10 — FINAL INTEGRATION & REGRESSION")
    print("=" * 72)
    print(f"Project root: {ROOT}")
    print()

    # ------------------------------------------------------------------
    # 1–3. Boot, route inventory, health/readiness
    # ------------------------------------------------------------------
    try:
        route_paths = {getattr(r, "path", "") for r in app.routes}
        required_routes = {
            "/health",
            "/ready",
            "/api/v1/analyze/eml",
            "/api/v1/analyze/email",
            "/api/v1/analyze/text",
            "/api/v1/forensics/audit",
            "/api/v1/forensics/case/{case_id}",
            "/api/v2/emails/upload",
            "/api/v2/emails/analyze",
            "/api/v2/evidence/register",
            "/api/v2/cases",
            "/api/v2/campaigns",
            "/api/v2/dashboard/summary",
        }
        missing = sorted(required_routes - route_paths)
        record(
            "Application boot",
            True,
            f"FastAPI app imported; {len(route_paths)} routes registered",
        )
        record(
            "Required route inventory",
            not missing,
            "all required routes present" if not missing else f"missing={missing}",
        )
    except Exception as exc:
        record("Application boot", False, f"{type(exc).__name__}: {exc}")
        return 1

    with TestClient(app) as client:
        health = request_json(client, "GET", "/health")
        if health is not None:
            body = json_body(health)
            ok = health.status_code == 200 and body.get("status") == "healthy"
            record(
                "Health endpoint",
                ok,
                f"HTTP {health.status_code}, status={body.get('status')}, "
                f"version={body.get('version')}",
            )

        ready = request_json(client, "GET", "/ready")
        if ready is not None:
            body = json_body(ready)
            ok = ready.status_code == 200 and body.get("status") == "ready"
            record(
                "Readiness endpoint",
                ok,
                f"HTTP {ready.status_code}, status={body.get('status')}",
            )

        # ------------------------------------------------------------------
        # Common harmless email
        # ------------------------------------------------------------------
        base_payload = {
            "subject": "Project meeting",
            "sender": "alice@example.com",
            "recipient": "bob@example.com",
            "reply_to": "",
            "body": "Hello Bob, the project meeting is scheduled for tomorrow at 10 AM.",
            "html": "",
            "headers": "",
            "received_headers": "",
        }

        # ------------------------------------------------------------------
        # 4. V1 direct endpoint
        # ------------------------------------------------------------------
        v1_direct = request_json(client, "POST", "/api/v1/analyze/email", json=base_payload)
        if v1_direct is not None:
            body = json_body(v1_direct)
            ok = (
                v1_direct.status_code == 200
                and body.get("status") == "SUCCESS"
                and bool(body.get("case_id"))
                and isinstance(body.get("decision"), dict)
                and isinstance((body.get("report") or {}).get("threat_score"), dict)
            )
            record(
                "V1 direct email analysis",
                ok,
                f"HTTP {v1_direct.status_code}, case_id={body.get('case_id')}",
            )
            v1_case_id = body.get("case_id")
        else:
            v1_case_id = None

        # ------------------------------------------------------------------
        # 5. V1 EML upload
        # ------------------------------------------------------------------
        eml = (
            "From: alice@example.com\r\n"
            "To: bob@example.com\r\n"
            "Subject: Project meeting\r\n"
            "Date: Thu, 10 Sep 2026 10:00:00 +0530\r\n"
            "Message-ID: <netra-710@example.com>\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Hello Bob, the project meeting is scheduled for tomorrow at 10 AM.\r\n"
        ).encode()

        v1_upload = request_json(
            client,
            "POST",
            "/api/v1/analyze/eml",
            files={"file": ("integration_test.eml", eml, "message/rfc822")},
        )
        if v1_upload is not None:
            body = json_body(v1_upload)
            ok = (
                v1_upload.status_code == 200
                and body.get("status") == "SUCCESS"
                and bool(body.get("case_id"))
            )
            record(
                "V1 EML upload",
                ok,
                f"HTTP {v1_upload.status_code}, case_id={body.get('case_id')}",
            )
            v1_upload_case_id = body.get("case_id")
        else:
            v1_upload_case_id = None

        # ------------------------------------------------------------------
        # 6. V1 case retrieval + audit
        # ------------------------------------------------------------------
        if v1_upload_case_id:
            r = request_json(client, "GET", f"/api/v1/forensics/case/{v1_upload_case_id}")
            if r is not None:
                b = json_body(r)
                ok = r.status_code == 200 and b.get("status") == "SUCCESS" and bool(b.get("ledger"))
                record("V1 forensic case retrieval", ok, f"HTTP {r.status_code}")

        audit = request_json(client, "GET", "/api/v1/forensics/audit")
        if audit is not None:
            b = json_body(audit)
            ok = (
                audit.status_code == 200
                and b.get("valid") is True
                and b.get("status") not in {"ERROR", "CORRUPT"}
            )
            record(
                "V1 forensic ledger audit",
                ok,
                f"HTTP {audit.status_code}, status={b.get('status')}, valid={b.get('valid')}",
            )

        # ------------------------------------------------------------------
        # 7. V2 text analysis
        # ------------------------------------------------------------------
        v2_text = request_json(
            client,
            "POST",
            "/api/v2/emails/analyze",
            json=base_payload,
        )
        v2_email_id = None
        if v2_text is not None:
            b = json_body(v2_text)
            v2_email_id = b.get("email_id")
            ok = (
                v2_text.status_code == 200
                and b.get("status") == "SUCCESS"
                and bool(v2_email_id)
                and isinstance(b.get("evidence"), dict)
                and isinstance(b.get("findings"), list)
                and isinstance(b.get("limitations"), list)
            )
            record(
                "V2 text analysis",
                ok,
                f"HTTP {v2_text.status_code}, email_id={v2_email_id}",
            )

        # ------------------------------------------------------------------
        # 8. V2 EML upload + automatic evidence
        # ------------------------------------------------------------------
        v2_upload = request_json(
            client,
            "POST",
            "/api/v2/emails/upload",
            files={"file": ("integration_v2.eml", eml, "message/rfc822")},
        )
        v2_upload_id = None
        v2_evidence_id = None
        if v2_upload is not None:
            b = json_body(v2_upload)
            v2_upload_id = b.get("email_id")
            evidence_ref = b.get("evidence_reference") or {}
            v2_evidence_id = evidence_ref.get("evidence_id")
            ok = (
                v2_upload.status_code == 200
                and b.get("status") == "SUCCESS"
                and bool(v2_upload_id)
                and bool(v2_evidence_id)
                and evidence_ref.get("integrity_status") is not None
            )
            record(
                "V2 EML upload + automatic evidence",
                ok,
                f"HTTP {v2_upload.status_code}, email_id={v2_upload_id}, "
                f"evidence_id={v2_evidence_id}",
            )

        target_email = v2_upload_id or v2_email_id

        # ------------------------------------------------------------------
        # 9. V2 email detail/findings/trace/graph/relationships
        # ------------------------------------------------------------------
        if target_email:
            checks = [
                ("V2 email detail", f"/api/v2/emails/{target_email}", {"email_id": target_email}),
                ("V2 findings", f"/api/v2/emails/{target_email}/findings", {"email_id": target_email}),
                ("V2 trace", f"/api/v2/emails/{target_email}/trace", {"email_id": target_email}),
                ("V2 graph", f"/api/v2/emails/{target_email}/graph", {"email_id": target_email}),
                ("V2 relationships", f"/api/v2/emails/{target_email}/relationships", {"email_id": target_email}),
            ]
            for name, path, required in checks:
                r = request_json(client, "GET", path)
                if r is not None:
                    b = json_body(r)
                    ok = r.status_code == 200 and all(b.get(k) == v for k, v in required.items())
                    record(name, ok, f"HTTP {r.status_code}")

            corr = request_json(client, "POST", f"/api/v2/emails/{target_email}/correlate")
            if corr is not None:
                record(
                    "V2 correlation endpoint",
                    corr.status_code == 200,
                    f"HTTP {corr.status_code}",
                )

        # ------------------------------------------------------------------
        # 10. Campaign lifecycle
        # ------------------------------------------------------------------
        campaign = request_json(
            client,
            "POST",
            "/api/v2/campaigns",
            json={
                "name": "NETRA 7.10 Integration Campaign",
                "description": "Temporary regression-test campaign",
                "status": "suspected",
            },
        )
        campaign_id = None
        if campaign is not None:
            b = json_body(campaign)
            campaign_id = b.get("campaign_id")
            record(
                "Campaign create",
                campaign.status_code == 200 and bool(campaign_id),
                f"HTTP {campaign.status_code}, campaign_id={campaign_id}",
            )

        if campaign_id:
            r = request_json(client, "GET", f"/api/v2/campaigns/{campaign_id}")
            if r is not None:
                record("Campaign retrieve", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(
                client,
                "PATCH",
                f"/api/v2/campaigns/{campaign_id}",
                json={"status": "under_review"},
            )
            if r is not None:
                record("Campaign update", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(client, "GET", "/api/v2/campaigns")
            if r is not None:
                b = json_body(r)
                record(
                    "Campaign list",
                    r.status_code == 200 and isinstance(b.get("campaigns"), list),
                    f"HTTP {r.status_code}",
                )

            r = request_json(client, "GET", f"/api/v2/campaigns/{campaign_id}/emails")
            if r is not None:
                record("Campaign email listing", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(client, "GET", f"/api/v2/campaigns/{campaign_id}/relationships")
            if r is not None:
                record("Campaign relationships", r.status_code == 200, f"HTTP {r.status_code}")

        # ------------------------------------------------------------------
        # 11–12. Case lifecycle
        # ------------------------------------------------------------------
        case = request_json(
            client,
            "POST",
            "/api/v2/cases",
            json={
                "title": "NETRA 7.10 Integration Case",
                "description": "Temporary regression-test case",
                "status": "open",
                "severity": "medium",
                "priority": "normal",
                "analyst": "integration-test",
            },
        )
        case_id = None
        if case is not None:
            b = json_body(case)
            case_id = b.get("case_id") or b.get("id")
            record(
                "Case create",
                case.status_code == 200 and bool(case_id),
                f"HTTP {case.status_code}, case_id={case_id}",
            )

        if case_id:
            r = request_json(client, "GET", f"/api/v2/cases/{case_id}")
            if r is not None:
                record("Case retrieve", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(
                client,
                "PATCH",
                f"/api/v2/cases/{case_id}",
                json={"priority": "high", "severity": "medium"},
            )
            if r is not None:
                record("Case update", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(client, "GET", "/api/v2/cases")
            if r is not None:
                b = json_body(r)
                record(
                    "Case list",
                    r.status_code == 200 and isinstance(b.get("cases"), list),
                    f"HTTP {r.status_code}",
                )

            if target_email:
                r = request_json(
                    client,
                    "POST",
                    f"/api/v2/cases/{case_id}/emails/{target_email}",
                )
                if r is not None:
                    record("Case ↔ email link", r.status_code == 200, f"HTTP {r.status_code}")

            if campaign_id:
                r = request_json(
                    client,
                    "POST",
                    f"/api/v2/cases/{case_id}/campaigns/{campaign_id}",
                )
                if r is not None:
                    record("Case ↔ campaign link", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(
                client,
                "POST",
                f"/api/v2/cases/{case_id}/notes",
                json={"note": "7.10 integration test note", "actor": "integration-test"},
            )
            if r is not None:
                record("Case note", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(
                client,
                "POST",
                f"/api/v2/cases/{case_id}/tags",
                json={"tag": "integration-test"},
            )
            if r is not None:
                record("Case tag", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(client, "GET", f"/api/v2/cases/{case_id}/timeline")
            if r is not None:
                b = json_body(r)
                record(
                    "Case timeline",
                    r.status_code == 200 and isinstance(b.get("timeline"), list),
                    f"HTTP {r.status_code}",
                )

        # ------------------------------------------------------------------
        # 13–14. Evidence lifecycle
        # ------------------------------------------------------------------
        if v2_evidence_id:
            r = request_json(client, "GET", f"/api/v2/evidence/{v2_evidence_id}")
            if r is not None:
                record("Evidence retrieve", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(client, "GET", f"/api/v2/evidence/{v2_evidence_id}/verify")
            if r is not None:
                b = json_body(r)
                integrity_status = str(
                    b.get("integrity_status")
                    or b.get("status")
                    or b.get("verification_status")
                    or ""
                ).upper()
                explicit_valid = b.get("valid")
                ok = (
                    r.status_code == 200
                    and (
                        explicit_valid is True
                        or integrity_status in {
                            "VALID", "VERIFIED", "INTEGRAL", "INTACT", "MATCH", "OK"
                        }
                    )
                )
                record(
                    "Evidence verification",
                    ok,
                    f"HTTP {r.status_code}, valid={explicit_valid}, "
                    f"integrity_status={integrity_status or 'not-provided'}",
                )

            r = request_json(client, "GET", f"/api/v2/evidence/{v2_evidence_id}/versions")
            if r is not None:
                b = json_body(r)
                record(
                    "Evidence versions",
                    r.status_code == 200 and isinstance(b.get("versions"), list),
                    f"HTTP {r.status_code}",
                )

            version_eml = eml.replace(b"Project meeting", b"Project meeting - revised")
            r = request_json(
                client,
                "POST",
                f"/api/v2/evidence/{v2_evidence_id}/versions",
                files={"file": ("integration_v2_revision.eml", version_eml, "message/rfc822")},
                data={"reason": "7.10 integration regression"},
            )
            version_ok = False
            if r is not None:
                version_ok = r.status_code == 200
                record("Evidence new version", version_ok, f"HTTP {r.status_code}")

            r = request_json(client, "GET", f"/api/v2/evidence/{v2_evidence_id}/custody")
            if r is not None:
                b = json_body(r)
                record(
                    "Evidence custody",
                    r.status_code == 200 and isinstance(b.get("events"), list),
                    f"HTTP {r.status_code}",
                )

            if case_id:
                r = request_json(
                    client,
                    "POST",
                    f"/api/v2/cases/{case_id}/evidence/{v2_evidence_id}",
                )
                if r is not None:
                    record("Case ↔ evidence link", r.status_code == 200, f"HTTP {r.status_code}")

                r = request_json(client, "GET", f"/api/v2/cases/{case_id}/evidence")
                if r is not None:
                    b = json_body(r)
                    record(
                        "Case evidence listing",
                        r.status_code == 200 and isinstance(b.get("evidence"), list),
                        f"HTTP {r.status_code}",
                    )

                r = request_json(client, "GET", f"/api/v2/cases/{case_id}/custody")
                if r is not None:
                    b = json_body(r)
                    record(
                        "Case custody",
                        r.status_code == 200 and isinstance(b.get("events"), list),
                        f"HTTP {r.status_code}",
                    )

        # ------------------------------------------------------------------
        # 15. Report lifecycle
        # ------------------------------------------------------------------
        report_id = None
        if case_id:
            r = request_json(client, "POST", f"/api/v2/cases/{case_id}/reports?report_format=json")
            if r is not None:
                b = json_body(r)
                report_id = b.get("report_id") or b.get("id")
                record(
                    "JSON report generation",
                    r.status_code == 200 and bool(report_id),
                    f"HTTP {r.status_code}, report_id={report_id}",
                )

            r = request_json(client, "GET", f"/api/v2/cases/{case_id}/reports")
            if r is not None:
                b = json_body(r)
                record(
                    "Case report listing",
                    r.status_code == 200 and isinstance(b.get("reports"), list),
                    f"HTTP {r.status_code}",
                )

        if report_id:
            r = request_json(client, "GET", f"/api/v2/reports/{report_id}")
            if r is not None:
                record("Report retrieve", r.status_code == 200, f"HTTP {r.status_code}")

            r = request_json(client, "GET", f"/api/v2/reports/{report_id}/download")
            if r is not None:
                ok = r.status_code == 200 and len(r.content) > 0
                record(
                    "Report download",
                    ok,
                    f"HTTP {r.status_code}, bytes={len(r.content)}",
                )

        # ------------------------------------------------------------------
        # 16. Dashboard / email listing
        # ------------------------------------------------------------------
        r = request_json(client, "GET", "/api/v2/dashboard/summary")
        if r is not None:
            record("Dashboard summary", r.status_code == 200, f"HTTP {r.status_code}")

        r = request_json(client, "GET", "/api/v2/emails?limit=5&offset=0")
        if r is not None:
            record("V2 email listing", r.status_code == 200, f"HTTP {r.status_code}")

        # ------------------------------------------------------------------
        # 17. Intelligence endpoints
        # ------------------------------------------------------------------
        r = request_json(client, "GET", "/api/v2/intelligence/ip/127.0.0.1")
        if r is not None:
            b = json_body(r)
            # Exact provider shape can evolve; endpoint must respond successfully.
            record(
                "IP intelligence endpoint",
                r.status_code == 200 and isinstance(b, dict),
                f"HTTP {r.status_code}",
            )

        r = request_json(client, "GET", "/api/v2/intelligence/domain/example.com")
        if r is not None:
            b = json_body(r)
            record(
                "Domain intelligence endpoint",
                r.status_code == 200 and isinstance(b, dict),
                f"HTTP {r.status_code}",
            )

        # ------------------------------------------------------------------
        # 18. Validation / error-path smoke tests
        # ------------------------------------------------------------------
        r = request_json(
            client,
            "POST",
            "/api/v1/analyze/email",
            json={},
        )
        if r is not None:
            record(
                "Empty V1 email rejected",
                r.status_code == 400,
                f"HTTP {r.status_code}",
            )

        r = request_json(
            client,
            "POST",
            "/api/v1/analyze/eml",
            files={"file": ("not_email.txt", b"hello", "text/plain")},
        )
        if r is not None:
            record(
                "Wrong V1 file type rejected",
                r.status_code == 400,
                f"HTTP {r.status_code}",
            )

        r = request_json(
            client,
            "POST",
            "/api/v2/campaigns",
            json={"name": "", "status": "suspected"},
        )
        if r is not None:
            record(
                "Invalid campaign rejected",
                r.status_code == 400,
                f"HTTP {r.status_code}",
            )

        # ------------------------------------------------------------------
        # 19. SSRF safety smoke test
        # ------------------------------------------------------------------
        ssrf_payload = {
            "subject": "Internal diagnostic",
            "sender": "monitor@example.com",
            "recipient": "analyst@example.com",
            "body": "Please inspect http://127.0.0.1:8000/admin",
            "html": "",
            "headers": "",
            "received_headers": "",
        }
        r = request_json(client, "POST", "/api/v1/analyze/email", json=ssrf_payload)
        if r is not None:
            b = json_body(r)
            decision = b.get("decision") or {}
            score = decision.get("score", b.get("threat_score", 0))
            action = decision.get("action", "")
            classifications = decision.get("attack_classification", []) or []
            classification = str(decision.get("classification", ""))
            reasons = " ".join(str(x) for x in (decision.get("reasons", []) or []))
            classification_blob = " ".join(
                [classification] + [str(x) for x in classifications] + [reasons]
            )
            ok = (
                r.status_code == 200
                and int(score or 0) >= 75
                and str(action).upper() == "BLOCK"
                and "SSRF" in classification_blob.upper()
            )
            record(
                "SSRF block smoke test",
                ok,
                f"HTTP {r.status_code}, score={score}, action={action}, "
                f"attack_classification={classifications}",
            )

        # ------------------------------------------------------------------
        # 20. Deterministic regression, if available
        # ------------------------------------------------------------------
        corpus = load_corpus()
        if corpus:
            expected_threat = {
                "01_legitimate_meeting.eml": False,
                "02_legitimate_business.eml": False,
                "03_credential_phishing.eml": True,
                "04_urgent_phishing.eml": True,
                "05_bec_payment.eml": True,
                "06_suspicious_url.eml": True,
                "07_ssrf_localhost.eml": True,
                "08_executable_attachment.eml": True,
                "09_double_extension.eml": True,
                "10_macro_document.eml": True,
                "11_html_attachment.eml": True,
                "12_svg_attachment.eml": True,
                "13_suspicious_archive.eml": True,
                "14_mime_mismatch.eml": True,
                "15_punycode_url.eml": True,
                "16_raw_ip_url.eml": True,
                "17_reply_to_mismatch.eml": True,
                "18_mixed_attack.eml": True,
                "20_auth_unavailable.eml": False,
            }
            deterministic_pass = 0
            deterministic_total = len(expected_threat)
            robustness_ok = False

            for filename, expected in expected_threat.items():
                raw_case = corpus.get(filename)
                if raw_case is None:
                    continue
                r = request_json(
                    client,
                    "POST",
                    "/api/v1/analyze/eml",
                    files={"file": (filename, raw_case, "message/rfc822")},
                )
                if r is None:
                    continue
                b = json_body(r)
                decision = b.get("decision") or {}
                scoring = b.get("scoring") or {}
                risk = str(
                    decision.get("risk")
                    or decision.get("risk_level")
                    or scoring.get("severity")
                    or "SAFE"
                ).upper()
                action = str(decision.get("action") or "").upper()
                observed = risk != "SAFE" or action in {"REVIEW", "QUARANTINE", "BLOCK"}
                if r.status_code == 200 and observed == expected:
                    deterministic_pass += 1

            malformed = corpus.get("19_malformed_like.eml")
            if malformed is not None:
                r = request_json(
                    client,
                    "POST",
                    "/api/v1/analyze/eml",
                    files={"file": ("19_malformed_like.eml", malformed, "message/rfc822")},
                )
                if r is not None:
                    b = json_body(r)
                    decision = b.get("decision") or {}
                    risk = str(
                        decision.get("risk")
                        or decision.get("risk_level")
                        or "SAFE"
                    ).upper()
                    action = str(decision.get("action") or "").upper()
                    # Robustness is about safe handling/no crash. LOW/REVIEW is
                    # accepted and is intentionally not counted as an FP.
                    robustness_ok = (
                        r.status_code == 200
                        and risk in {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                        and action in {"ALLOW", "REVIEW", "QUARANTINE", "BLOCK"}
                    )

            record(
                "Deterministic threat regression",
                deterministic_pass == deterministic_total,
                f"{deterministic_pass}/{deterministic_total} threat expectations matched",
            )
            record(
                "Malformed-input robustness",
                robustness_ok,
                "malformed-like sample handled without crash; REVIEW is accepted",
            )
        else:
            record(
                "Deterministic threat regression",
                True,
                "corpus not present; run the separate deterministic evaluator when available",
                warning=True,
            )

        # ------------------------------------------------------------------
        # 21. Final ledger integrity
        # ------------------------------------------------------------------
        r = request_json(client, "GET", "/api/v1/forensics/audit")
        if r is not None:
            b = json_body(r)
            ok = (
                r.status_code == 200
                and b.get("valid") is True
                and b.get("status") not in {"ERROR", "CORRUPT"}
            )
            record(
                "Final ledger integrity",
                ok,
                f"HTTP {r.status_code}, status={b.get('status')}, valid={b.get('valid')}, "
                f"records={b.get('total_records')}",
            )

    print()
    print("=" * 72)
    print("7.10 RESULT")
    print("=" * 72)
    print(f"PASS : {PASS}")
    print(f"WARN : {WARN}")
    print(f"FAIL : {FAIL}")
    print(f"CHECKS: {len(RESULTS)}")
    print()

    if FAIL:
        print("7.10 STATUS: FAIL")
        print("Fix only the failing integration/regression checks.")
        return 1

    if WARN:
        print("7.10 STATUS: PASS WITH WARNINGS")
        print("Warnings are non-blocking; review them before final demo.")
        return 0

    print("7.10 STATUS: PASS")
    print("Final integration/regression checks are clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
