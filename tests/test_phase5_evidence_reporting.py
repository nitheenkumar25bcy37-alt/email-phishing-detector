import hashlib
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.database import ForensicLedgerDB
from backend.evidence_service import EvidenceService
from backend.main import app
from backend.report_service import ReportService


class Phase5EvidenceReportingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.db = ForensicLedgerDB(str(self.root / "ledger.db"))
        self.evidence = EvidenceService(self.db, str(self.root / "evidence"))
        self.reports = ReportService(self.db, self.evidence, str(self.root / "evidence"))

    def tearDown(self):
        self.directory.cleanup()

    def case(self):
        now_case = {"title": "Evidence investigation", "description": "Test case", "status": "open", "severity": "high", "priority": "normal", "analyst": "tester", "case_id": "case_test", "created_at": "2026-09-09T00:00:00+00:00", "updated_at": "2026-09-09T00:00:00+00:00", "tags": []}
        self.db.create_case(now_case)
        return "case_test"

    def test_registration_hash_deduplication_and_custody(self):
        case_id = self.case()
        raw = b"Subject: Evidence\n\nOriginal"
        item = self.evidence.register(raw, "message.eml", "message/rfc822", case_id=case_id)
        self.assertEqual(item["sha256"], hashlib.sha256(raw).hexdigest())
        duplicate = self.evidence.register(raw, "message.eml", "message/rfc822", case_id=case_id)
        self.assertEqual(item["evidence_id"], duplicate["evidence_id"])
        events = self.evidence.custody(item["evidence_id"])
        self.assertGreaterEqual(len(events), 3)
        self.assertEqual(self.evidence.verify(item["evidence_id"])["integrity_status"], "verified")

    def test_integrity_failure_and_missing_file_are_structured(self):
        item = self.evidence.register(b"original", "message.eml", "message/rfc822")
        path = self.root / "evidence" / item["storage_reference"]
        path.write_bytes(b"modified")
        result = self.evidence.verify(item["evidence_id"])
        self.assertFalse(result["match"])
        self.assertEqual(result["integrity_status"], "failed")
        path.unlink()
        result = self.evidence.verify(item["evidence_id"])
        self.assertEqual(result["integrity_status"], "unavailable")
        self.assertFalse(result["match"])

    def test_version_does_not_overwrite_original(self):
        item = self.evidence.register(b"original", "message.eml", "message/rfc822")
        version = self.evidence.create_version(item["evidence_id"], b"replacement", "message.eml")
        versions = self.evidence.versions(item["evidence_id"])
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0]["sha256"], hashlib.sha256(b"original").hexdigest())
        self.assertEqual(version["version"], 2)
        self.assertEqual(self.evidence.verify(item["evidence_id"])["integrity_status"], "verified")

    def test_case_link_and_reports_json_html_pdf(self):
        case_id = self.case()
        analysis = {"email_id": "email_report", "evidence": {"sha256": "a" * 64}, "classification": "Phishing", "risk_score": 80, "findings": [], "parsed": {"metadata": {"subject": "Test"}, "origin_trace": {}, "ip_intelligence": [], "domain_intelligence": {}}}
        self.db.record_v2_analysis("email_report", "a" * 64, analysis)
        item = self.evidence.register(b"raw email", "message.eml", "message/rfc822", email_id="email_report")
        self.evidence.link_case(item["evidence_id"], case_id)
        for output_format in ("json", "html", "pdf"):
            report = self.reports.generate(case_id, output_format)
            self.assertEqual(report["format"], output_format)
            self.assertTrue(report["integrity_verified"])
            self.assertIn(item["sha256"], self.reports.get(report["report_id"])["evidence_inventory"][0]["sha256"])
            self.assertTrue((self.root / "evidence" / report["download_reference"]).is_file())

    def test_unsafe_filename_and_missing_records(self):
        with self.assertRaises(ValueError):
            self.evidence.register(b"x", "..\\outside.eml", "message/rfc822")
        with self.assertRaises(KeyError):
            self.evidence.verify("missing")
        with self.assertRaises(KeyError):
            self.reports.generate("missing", "json")

    def test_api_evidence_report_and_download_flow(self):
        client = TestClient(app)
        case = client.post("/api/v2/cases", json={"title": "API evidence case"}).json()
        registered = client.post("/api/v2/evidence/register", files={"file": ("api.eml", b"Subject: API\n\nBody", "message/rfc822")}, data={"case_id": case["case_id"]})
        self.assertEqual(registered.status_code, 200)
        evidence_id = registered.json()["evidence_id"]
        self.assertEqual(client.get(f"/api/v2/evidence/{evidence_id}/verify").status_code, 200)
        report = client.post(f"/api/v2/cases/{case['case_id']}/reports?report_format=html")
        self.assertEqual(report.status_code, 200)
        report_id = report.json()["report_id"]
        self.assertEqual(client.get(f"/api/v2/reports/{report_id}").status_code, 200)
        download = client.get(f"/api/v2/reports/{report_id}/download")
        self.assertEqual(download.status_code, 200)
        self.assertIn(b"NETRA-Mail", download.content)
        self.assertIn("evidence_registered", {event["event_type"] for event in client.get(f"/api/v2/evidence/{evidence_id}/custody").json()["events"]})


if __name__ == "__main__":
    unittest.main()
