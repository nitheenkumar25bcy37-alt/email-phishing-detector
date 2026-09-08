import unittest

from backend.attachment_analyzer import AttachmentAnalyzer
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.url_analyzer import URLAnalyzer
from backend.url_expander import URLExpander


class FeatureTests(unittest.TestCase):
    def test_executable_attachment(self):
        result = AttachmentAnalyzer.analyze([{
            "filename": "invoice.exe",
            "content_type": "application/octet-stream",
            "size_bytes": 12,
        }])
        self.assertEqual(result["suspicious_attachment_count"], 1)
        self.assertGreaterEqual(result["score"], 50)

    def test_double_extension(self):
        result = AttachmentAnalyzer.analyze([{
            "filename": "invoice.pdf.exe",
            "content_type": "application/octet-stream",
        }])
        self.assertIn("misleading double extension", result["attachments"][0]["reasons"][1])

    def test_archive_is_reviewable_not_executable(self):
        result = AttachmentAnalyzer.analyze([{
            "filename": "documents.zip",
            "content_type": "application/zip",
        }])
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertLess(result["score"], 50)

    def test_pdf_attachment_is_not_suspicious_by_extension(self):
        result = AttachmentAnalyzer.analyze([{
            "filename": "invoice.pdf",
            "content_type": "application/pdf",
        }])
        self.assertEqual(result["suspicious_attachment_count"], 0)
        self.assertEqual(result["score"], 0)

    def test_homograph_and_subdomain_signals(self):
        homograph = URLAnalyzer.analyze_url("https://раypal.com/verify")
        subdomain = URLAnalyzer.analyze_url("https://bank-login.attacker.com/verify")
        self.assertTrue(homograph["punycode"])
        self.assertIn("misleading_subdomain", subdomain["suspicious_keywords"])

    def test_explicit_phishing_hostname(self):
        result = URLAnalyzer.analyze_url("https://phishing-bank.ru/payment")
        self.assertGreaterEqual(result["risk_score"], 40)

    def test_reply_to_mismatch(self):
        parsed = {
            "metadata": {
                "from": "noreply@legitimate-bank.com",
                "reply_to": "support@phishing-bank.ru",
                "return_path": "",
            },
            "authentication_headers": {
                "authentication_results": "spf=pass dkim=pass dmarc=pass",
            },
            "network_chain": [],
        }
        result = HeaderForensicAnalyzer.analyze(parsed)
        self.assertTrue(result["alignment"]["has_mismatch"])
        self.assertGreaterEqual(result["header_risk_score"], 10)

    def test_expander_rejects_unsupported_scheme(self):
        result = URLExpander.expand("javascript:alert(1)")
        self.assertFalse(result["expanded"])
        self.assertEqual(result["error"], "unsupported_url")


if __name__ == "__main__":
    unittest.main()