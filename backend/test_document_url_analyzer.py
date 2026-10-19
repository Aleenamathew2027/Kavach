"""
=============================================================================
KAVACH — Document URL Analyzer Test Suite
=============================================================================
Tests URL security analysis integration with the Hybrid URL Engine (analyze_link_url).
Verifies safe, suspicious, and high-risk URL analysis, multi-URL risk aggregation,
empty list handling, exception safety, and 0-100 risk score bounds.
=============================================================================
"""

import unittest
from unittest.mock import patch

from app.services.document_url_analyzer import analyze_extracted_url_list, extract_and_analyze_document_urls


class TestDocumentURLAnalyzer(unittest.TestCase):

    def test_safe_url_analysis(self):
        items = [{"url": "https://www.google.com", "source": "document_text"}]
        res = analyze_extracted_url_list(items)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 1)
        self.assertEqual(res["overall_url_verdict"], "SAFE")
        self.assertLess(res["highest_url_risk_score"], 30)
        self.assertEqual(res["urls"][0]["verdict"], "SAFE")

    def test_suspicious_url_analysis(self):
        items = [{"url": "http://example-login.com/verify", "source": "document_text"}]
        res = analyze_extracted_url_list(items)

        self.assertTrue(res["success"])
        self.assertIn(res["overall_url_verdict"], ["SUSPICIOUS", "HIGH_RISK"])
        self.assertGreaterEqual(res["highest_url_risk_score"], 30)
        self.assertEqual(res["flagged_urls_count"], 1)

    def test_high_risk_url_analysis(self):
        items = [{"url": "https://secure-login-example.com@evil.example/verify", "source": "document_text"}]
        res = analyze_extracted_url_list(items)

        self.assertTrue(res["success"])
        self.assertEqual(res["overall_url_verdict"], "HIGH_RISK")
        self.assertGreaterEqual(res["highest_url_risk_score"], 60)
        self.assertEqual(res["urls"][0]["verdict"], "HIGH RISK")
        self.assertTrue(len(res["urls"][0]["indicators"]) > 0)

    def test_multiple_url_analysis(self):
        items = [
            {"url": "https://www.wikipedia.org", "source": "document_text"},
            {"url": "http://malicious-update-app.top/payload.apk", "source": "document_text"},
        ]
        res = analyze_extracted_url_list(items)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 2)
        self.assertEqual(res["overall_url_verdict"], "HIGH_RISK")
        self.assertGreaterEqual(res["highest_url_risk_score"], 60)
        self.assertEqual(res["flagged_urls_count"], 1)

    def test_empty_url_list(self):
        res = analyze_extracted_url_list([])

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 0)
        self.assertEqual(res["overall_url_verdict"], "SAFE")
        self.assertEqual(res["highest_url_risk_score"], 0)
        self.assertEqual(res["flagged_urls_count"], 0)

    def test_scanner_exception_handling(self):
        items = [{"url": "https://invalid-test-url", "source": "document_text"}]
        with patch("app.services.document_url_analyzer.analyze_link_url", side_effect=Exception("Scanner failure")):
            res = analyze_extracted_url_list(items)

            self.assertTrue(res["success"])
            self.assertEqual(res["url_count"], 1)
            self.assertEqual(res["urls"][0]["verdict"], "UNKNOWN")
            self.assertIsNotNone(res["urls"][0]["error"])

    def test_ml_model_response_integration(self):
        text = "Visit https://www.google.com for info."
        res = extract_and_analyze_document_urls(text)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 1)
        url_data = res["urls"][0]
        self.assertIsNotNone(url_data.get("model"))
        self.assertIsNotNone(url_data.get("ml_verdict"))
        self.assertGreaterEqual(url_data["risk_score"], 0)
        self.assertLessEqual(url_data["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
