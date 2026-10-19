"""
=============================================================================
KAVACH — Document URL Extractor Test Suite
=============================================================================
Tests safe URL extraction, regex pattern matching, punctuation trimming,
deduplication, HTTP/HTTPS/www formatting, and zero-network request safety.
=============================================================================
"""

import unittest
from app.services.document_url_extractor import extract_urls_from_text, clean_extracted_url


class TestDocumentURLExtractor(unittest.TestCase):

    def test_extract_single_url(self):
        text = "Please visit our official website at https://www.google.com for information."
        res = extract_urls_from_text(text)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 1)
        self.assertEqual(res["urls"][0]["url"], "https://www.google.com")
        self.assertEqual(res["urls"][0]["source"], "document_text")

    def test_extract_multiple_urls(self):
        text = "Check https://www.wikipedia.org and also http://example.com/login for details."
        res = extract_urls_from_text(text)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 2)
        urls = [u["url"] for u in res["urls"]]
        self.assertIn("https://www.wikipedia.org", urls)
        self.assertIn("http://example.com/login", urls)

    def test_duplicate_url_removal(self):
        text = "Visit https://example.com or click https://example.com again (https://EXAMPLE.COM)."
        res = extract_urls_from_text(text)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 1)
        self.assertEqual(res["urls"][0]["url"], "https://example.com")

    def test_urls_surrounded_by_punctuation(self):
        text = 'Please verify here: (https://example.com/login). Or check "http://test.org/auth",'
        res = extract_urls_from_text(text)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 2)
        urls = [u["url"] for u in res["urls"]]
        self.assertIn("https://example.com/login", urls)
        self.assertIn("http://test.org/auth", urls)

    def test_no_urls_found(self):
        text = "This text contains no web links or URL patterns whatsoever."
        res = extract_urls_from_text(text)

        self.assertTrue(res["success"])
        self.assertEqual(res["url_count"], 0)
        self.assertEqual(len(res["urls"]), 0)

    def test_http_and_https_urls(self):
        text = "Insecure: http://insecure-site.com vs Secure: https://secure-site.com"
        res = extract_urls_from_text(text)

        self.assertEqual(res["url_count"], 2)
        schemes = [u["url"].split("://")[0] for u in res["urls"]]
        self.assertIn("http", schemes)
        self.assertIn("https", schemes)

    def test_www_url_formatting(self):
        text = "Visit www.example.org for updates."
        res = extract_urls_from_text(text)

        self.assertEqual(res["url_count"], 1)
        self.assertEqual(res["urls"][0]["url"], "https://www.example.org")

    def test_invalid_malformed_url_cleaning(self):
        self.assertIsNone(clean_extracted_url("ht"))
        self.assertIsNone(clean_extracted_url(":::"))
        self.assertEqual(clean_extracted_url("(https://test.com/login)."), "https://test.com/login")

    def test_url_extraction_from_suspicious_scam_text(self):
        text = "URGENT BANK ALERT: Account blocked. Click https://secure-login-example.com@evil.example/verify or http://bit.ly/claim-bank-reward immediately!"
        res = extract_urls_from_text(text)

        self.assertEqual(res["url_count"], 2)
        raw_urls = [u["raw_extracted"] for u in res["urls"]]
        self.assertIn("https://secure-login-example.com@evil.example/verify", raw_urls)
        self.assertIn("http://bit.ly/claim-bank-reward", raw_urls)

    def test_url_count_correctness(self):
        text = "Link 1: https://a.com, Link 2: https://b.com, Link 3: https://c.com"
        res = extract_urls_from_text(text)

        self.assertEqual(res["url_count"], 3)


if __name__ == "__main__":
    unittest.main()
