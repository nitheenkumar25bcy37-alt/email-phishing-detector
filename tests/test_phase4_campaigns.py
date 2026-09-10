import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.campaign_correlator import CampaignCorrelator
from backend.database import ForensicLedgerDB
from backend.services.campaign_service import CampaignService
from backend.services.case_service import CaseService
from fastapi.testclient import TestClient
from backend.main import app


class Phase4CampaignTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = ForensicLedgerDB(str(Path(self.directory.name) / "phase4.db"))
        self.campaigns = CampaignService(self.db)
        self.cases = CaseService(self.db)

    def tearDown(self):
        self.directory.cleanup()

    @staticmethod
    def analysis(email_id, sender="sender@evil.test", reply_to="", attachment="", url="https://evil.test/login", subject="Urgent invoice", body="Please pay invoice", include_brand=True):
        findings = [{"category": "URL", "rule": "suspicious_url_features", "severity": "high", "confidence": 0.8, "evidence": {"brand": "Example"}}] if include_brand else []
        return {"email_id": email_id, "evidence": {"sha256": email_id + "hash"}, "risk_score": 80, "findings": findings, "parsed": {"metadata": {"from": sender, "reply_to": reply_to, "subject": subject, "message_id": f"<{email_id}@evil.test>"}, "body": {"plain": body, "visible_text": body}, "url_references": [{"href": url}], "attachments": ([{"sha256": attachment}] if attachment else []), "origin_trace": {"origin_candidates": [{"ip": "8.8.8.8", "intelligence": {"asn": "AS123"}}]}, "network_chain": [{"extracted_ips": ["8.8.8.8"], "ip_classifications": ["public"]}], "domain_intelligence": {"domains": [{"impersonated_brands": ["Example"] if include_brand else []}]}, "ip_intelligence": [{"asn": "AS123"}]}}

    def test_shared_attachment_and_url_confidence(self):
        first = self.analysis("email_a", attachment="same-hash")
        second = self.analysis("email_b", attachment="same-hash")
        relationships = CampaignCorrelator.correlate("email_b", second, [first])
        self.assertTrue(relationships)
        relationship = relationships[0]
        self.assertGreaterEqual(relationship["confidence"], 0.98)
        self.assertTrue(relationship["requires_review"])
        self.assertTrue(any("does not prove" in item for item in relationship["limitations"]))

    def test_weak_generic_domain_is_excluded_and_combined_indicators_help(self):
        one = self.analysis("email_a", sender="one@gmail.com", url="https://gmail.com/a", subject="Hello one", body="Different content one", include_brand=False)
        two = self.analysis("email_b", sender="two@gmail.com", url="https://gmail.com/b", subject="Hello two", body="Different content two", include_brand=False)
        self.assertEqual(CampaignCorrelator.correlate("email_b", two, [one]), [])
        three = self.analysis("email_c", sender="same@evil.test", reply_to="reply@evil.test", attachment="hash")
        four = self.analysis("email_d", sender="same@evil.test", reply_to="reply@evil.test", attachment="hash")
        relationship = CampaignCorrelator.correlate("email_d", four, [three])[0]
        self.assertLessEqual(relationship["confidence"], 0.99)
        self.assertGreaterEqual(len(relationship["evidence"]), 3)

    def test_duplicate_relationship_prevention_and_campaign_reuse(self):
        first = self.analysis("email_a", attachment="shared")
        second = self.analysis("email_b", attachment="shared")
        self.db.record_v2_analysis("email_a", "email_ahash", first)
        self.db.record_v2_analysis("email_b", "email_bhash", second)
        result_one = self.campaigns.correlate("email_b")
        result_two = self.campaigns.correlate("email_b")
        self.assertEqual(result_one["new_relationships"], 1)
        self.assertEqual(result_two["new_relationships"], 0)
        self.assertEqual(len(self.db.list_campaigns()), 1)
        self.assertEqual(len(self.db.get_campaign_emails(self.db.list_campaigns()[0]["campaign_id"])), 2)

    def test_case_lifecycle_and_timeline_persists(self):
        email = self.analysis("email_a")
        self.db.record_v2_analysis("email_a", "email_hash", email)
        case = self.cases.create({"title": "Investigation", "severity": "high", "priority": "urgent"})
        self.cases.add_email(case["case_id"], "email_a")
        self.cases.add_note(case["case_id"], "Review shared indicators.")
        self.cases.add_tag(case["case_id"], "phishing")
        updated = self.cases.update(case["case_id"], {"status": "investigating"})
        self.assertEqual(updated["status"], "investigating")
        timeline = self.db.get_case_timeline(case["case_id"])
        self.assertGreaterEqual(len(timeline), 5)
        reopened = ForensicLedgerDB(self.db.db_path).get_case_record(case["case_id"])
        self.assertEqual(reopened["email_ids"], ["email_a"])
        self.assertIn("phishing", reopened["tags"])

    def test_missing_records_are_rejected(self):
        with self.assertRaises(KeyError):
            self.cases.add_email("missing", "email")
        with self.assertRaises(KeyError):
            self.cases.add_campaign("missing", "campaign")

    def test_api_campaign_and_case_mutations(self):
        client = TestClient(app)
        first = client.post("/api/v2/emails/analyze", json={"subject": "Shared invoice", "sender": "a@phase4.test", "body": "Please review https://phase4.test/invoice"})
        second = client.post("/api/v2/emails/analyze", json={"subject": "Shared invoice", "sender": "a@phase4.test", "body": "Please review https://phase4.test/invoice"})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        second_data = second.json()
        self.assertIn("correlation", second_data)
        self.assertGreaterEqual(second_data["correlation"]["relationships_found"], 1)
        email_id = second_data["email_id"]
        self.assertEqual(client.get(f"/api/v2/emails/{email_id}/relationships").status_code, 200)
        campaign_response = client.post("/api/v2/campaigns", json={"name": "Manual review"})
        self.assertEqual(campaign_response.status_code, 200)
        campaign_id = campaign_response.json()["campaign_id"]
        case_response = client.post("/api/v2/cases", json={"title": "Phase 4 case", "severity": "high"})
        self.assertEqual(case_response.status_code, 200)
        case_id = case_response.json()["case_id"]
        self.assertEqual(client.post(f"/api/v2/cases/{case_id}/emails", json={"email_id": email_id}).status_code, 200)
        self.assertEqual(client.post(f"/api/v2/cases/{case_id}/campaigns/{campaign_id}").status_code, 200)
        self.assertEqual(client.post(f"/api/v2/cases/{case_id}/notes", json={"note": "Confirm shared indicators."}).status_code, 200)
        self.assertEqual(client.post(f"/api/v2/cases/{case_id}/tags", json={"tag": "needs-review"}).status_code, 200)
        timeline = client.get(f"/api/v2/cases/{case_id}/timeline")
        self.assertEqual(timeline.status_code, 200)
        self.assertGreaterEqual(len(timeline.json()["timeline"]), 5)
        self.assertEqual(client.patch(f"/api/v2/campaigns/{campaign_id}", json={"status": "under_review"}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
