"""
=============================================================================
KAVACH — URL Phishing ML & Hybrid Detector Test Suite
=============================================================================
Tests ML model loading, 32-feature lexical extractor, ML prediction probabilities,
hybrid combined scoring engine, and edge case URL inputs.
=============================================================================
"""

import unittest
from app.ai.url_feature_extractor import URLFeatureExtractor, FEATURE_NAMES
from app.ai.url_detector import URLPhishingDetector, predict_url_phishing
from app.services.link_scanner import analyze_link_url


class TestURLDetector(unittest.TestCase):

    def test_feature_extractor_shape_and_names(self):
        extractor = URLFeatureExtractor()
        url = "https://secure-login-bank.xyz/verify?token=123"
        feats = extractor.transform([url])
        self.assertEqual(feats.shape, (1, 32))
        self.assertEqual(len(FEATURE_NAMES), 32)
        # Check URL length feature
        self.assertGreater(feats[0][0], 10)

    def test_ml_model_singleton_loading(self):
        detector = URLPhishingDetector.get_instance()
        self.assertTrue(detector.is_loaded)
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.extractor)

    def test_predict_benign_google_url(self):
        res = predict_url_phishing("https://www.google.com")
        self.assertEqual(res["prediction"], "SAFE")
        self.assertGreater(res["safe_probability"], 80.0)

    def test_predict_benign_wikipedia_url(self):
        res = predict_url_phishing("https://www.wikipedia.org")
        self.assertEqual(res["prediction"], "SAFE")
        self.assertGreater(res["safe_probability"], 80.0)

    def test_predict_phishing_login_url(self):
        res = predict_url_phishing("http://example-login.com/verify")
        self.assertEqual(res["prediction"], "PHISHING")
        self.assertGreater(res["phishing_probability"], 70.0)

    def test_predict_phishing_at_obfuscation(self):
        res = predict_url_phishing("https://secure-login-example.com@evil.example/verify")
        self.assertEqual(res["prediction"], "PHISHING")
        self.assertGreater(res["phishing_probability"], 70.0)

    def test_predict_raw_ip(self):
        res = predict_url_phishing("https://192.168.1.1/login")
        self.assertEqual(res["prediction"], "PHISHING")
        self.assertGreater(res["phishing_probability"], 70.0)

    def test_predict_punycode_url(self):
        res = predict_url_phishing("https://xn--sbi-onlne-bank-82b.com/login")
        self.assertEqual(res["prediction"], "PHISHING")

    def test_predict_shortened_url(self):
        res = predict_url_phishing("https://bit.ly/claim-bank-reward")
        self.assertEqual(res["prediction"], "PHISHING")

    def test_predict_executable_apk_download(self):
        res = predict_url_phishing("http://malicious-update-app.top/payload.apk")
        self.assertEqual(res["prediction"], "PHISHING")
        self.assertGreater(res["phishing_probability"], 85.0)

    def test_hybrid_engine_integration_safe(self):
        res = analyze_link_url("https://www.google.com")
        self.assertEqual(res["verdict"], "SAFE")
        self.assertEqual(res["ml_verdict"], "SAFE")
        self.assertIn("Hybrid URL", res["analysis_type"])
        self.assertIn("Random Forest", res["model"])
        self.assertLess(res["risk_score"], 30)

    def test_hybrid_engine_integration_high_risk(self):
        res = analyze_link_url("https://secure-login-example.com@evil.example/verify")
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertEqual(res["ml_verdict"], "PHISHING")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertGreaterEqual(res["heuristic_score"], 40)
        self.assertGreaterEqual(res["ml_phishing_probability"], 70.0)

    def test_malformed_url_handling(self):
        res = analyze_link_url("ht tp://bad url with spaces")
        self.assertIn(res["verdict"], ["HIGH RISK", "SUSPICIOUS"])
        self.assertGreaterEqual(res["risk_score"], 30)

    def test_empty_url_handling(self):
        res = analyze_link_url("")
        self.assertEqual(res["verdict"], "SAFE")
        self.assertEqual(res["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
