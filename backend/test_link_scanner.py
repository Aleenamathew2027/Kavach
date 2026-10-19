"""
Comprehensive Unit Test Suite for Kavach Static Link Scanner.
Tests 20+ URL security signals, risk scoring logic, and verdict classification.
"""

import unittest
from app.services.link_scanner import analyze_link_url


class TestLinkScanner(unittest.TestCase):

    def test_safe_google_url(self):
        url = "https://www.google.com"
        res = analyze_link_url(url)
        self.assertEqual(res["verdict"], "SAFE")
        self.assertLess(res["risk_score"], 30)
        self.assertTrue("Hybrid" in res["analysis_type"] or "Heuristic" in res["analysis_type"])
        self.assertTrue(any("HTTPS" in r for r in res["reasons"]))


    def test_safe_wikipedia_url(self):
        url = "https://www.wikipedia.org"
        res = analyze_link_url(url)
        self.assertEqual(res["verdict"], "SAFE")
        self.assertLess(res["risk_score"], 30)

    def test_suspicious_http_login_url(self):
        url = "http://example-login.com/verify"
        res = analyze_link_url(url)
        self.assertIn(res["verdict"], ["SUSPICIOUS", "HIGH RISK"])
        self.assertGreaterEqual(res["risk_score"], 30)
        self.assertTrue(any("HTTP" in ind for ind in res["indicators"]))

    def test_high_risk_at_symbol_obfuscation(self):
        url = "https://secure-login-example.com@evil.example/verify"
        res = analyze_link_url(url)
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertTrue(any("@" in ind or "Userinfo" in ind for ind in res["indicators"]))

    def test_high_risk_raw_ip_address(self):
        url = "https://192.168.1.1/login"
        res = analyze_link_url(url)
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertTrue(any("IP Address" in ind for ind in res["indicators"]))

    def test_url_shortener(self):
        url = "https://bit.ly/claim-bank-reward"
        res = analyze_link_url(url)
        self.assertGreaterEqual(res["risk_score"], 25)
        self.assertTrue(any("Shortener" in ind for ind in res["indicators"]))

    def test_punycode_homograph(self):
        url = "https://xn--sbi-onlne-bank-82b.com/login"
        res = analyze_link_url(url)
        self.assertGreaterEqual(res["risk_score"], 35)
        self.assertTrue(any("Punycode" in ind for ind in res["indicators"]))

    def test_executable_apk_download(self):
        url = "http://malicious-update-app.top/payload.apk"
        res = analyze_link_url(url)
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertTrue(any("Executable" in ind or "APK" in ind for ind in res["indicators"]))

    def test_empty_url(self):
        res = analyze_link_url("")
        self.assertEqual(res["verdict"], "SAFE")
        self.assertEqual(res["risk_score"], 0)

    def test_malformed_url(self):
        res = analyze_link_url("ht tp://bad link with spaces:invalid:port")
        self.assertIn(res["verdict"], ["HIGH RISK", "SUSPICIOUS"])

    def test_very_long_url_with_query_params(self):
        url = "https://secure-portal-update.xyz/auth/login?session=12345&redirect=http://evil.com&token=secret&target=account&update=true"
        res = analyze_link_url(url)
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertGreaterEqual(len(res["indicators"]), 3)

    def test_subdomains_excessive(self):
        url = "https://login.verify.account.update.bank.secure-portal.com"
        res = analyze_link_url(url)
        self.assertGreaterEqual(res["risk_score"], 35)
        self.assertTrue(any("Subdomain" in ind for ind in res["indicators"]))


if __name__ == "__main__":
    unittest.main()
