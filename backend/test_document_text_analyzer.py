"""
=============================================================================
KAVACH — Document Text Analyzer Test Suite
=============================================================================
Tests document text scam classification reusing the trained Message ML model.
Verifies safe text, payment requests, OTP harvesting, fake prizes, job scams,
OCR status handling (NO_TEXT_FOUND, OCR_UNAVAILABLE, FAILED), explainable
indicators, and risk score boundaries (0-100).
=============================================================================
"""

import unittest
from app.services.document_text_analyzer import analyze_document_extracted_text


class TestDocumentTextAnalyzer(unittest.TestCase):

    def test_safe_document_text(self):
        ocr_res = {
            "success": True,
            "extracted_text": "This is an official meeting agenda for the annual community project review.",
            "ocr_status": "SUCCESS",
            "ocr_confidence": None,
            "character_count": 75,
            "word_count": 11,
            "page_count": 1,
            "error": None,
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"], "SAFE")
        self.assertLess(res["risk_score"], 30)
        self.assertIsNone(res["error"])
        self.assertGreaterEqual(res["confidence"], 0.0)

    def test_suspicious_payment_request(self):
        ocr_res = {
            "success": True,
            "extracted_text": "URGENT NOTICE: Your bank account will be blocked within 24 hours. Please wire transfer funds immediately.",
            "ocr_status": "SUCCESS",
            "ocr_confidence": None,
            "character_count": 105,
            "word_count": 16,
            "page_count": 1,
            "error": None,
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertTrue(res["success"])
        self.assertIn(res["verdict"], ["SUSPICIOUS", "HIGH_RISK"])
        self.assertGreaterEqual(res["risk_score"], 30)
        self.assertTrue(any("Urgency" in ind or "Financial" in ind for ind in res["indicators"]))

    def test_otp_password_request(self):
        ocr_res = {
            "success": True,
            "extracted_text": "SECURITY ALERT: Share your 6-digit OTP code and netbanking password to verify identity immediately.",
            "ocr_status": "SUCCESS",
            "ocr_confidence": None,
            "character_count": 98,
            "word_count": 13,
            "page_count": 1,
            "error": None,
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"], "HIGH_RISK")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertTrue(any("Credential" in ind or "OTP" in ind for ind in res["indicators"]))

    def test_fake_prize_claim(self):
        ocr_res = {
            "success": True,
            "extracted_text": "CONGRATULATIONS! You have won $50,000 in the international lottery. Claim your reward immediately.",
            "ocr_status": "SUCCESS",
            "ocr_confidence": None,
            "character_count": 99,
            "word_count": 13,
            "page_count": 1,
            "error": None,
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertTrue(res["success"])
        self.assertIn(res["verdict"], ["SUSPICIOUS", "HIGH_RISK"])
        self.assertGreaterEqual(res["risk_score"], 35)

    def test_suspicious_job_offer(self):
        ocr_res = {
            "success": True,
            "extracted_text": "Guaranteed work from home job offer: Earn $500 daily. Pay registration fee via Paytm immediately to activate.",
            "ocr_status": "SUCCESS",
            "ocr_confidence": None,
            "character_count": 110,
            "word_count": 16,
            "page_count": 1,
            "error": None,
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertTrue(res["success"])
        self.assertIn(res["verdict"], ["SUSPICIOUS", "HIGH_RISK"])
        self.assertGreaterEqual(res["risk_score"], 35)

    def test_empty_extracted_text(self):
        ocr_res = {
            "success": True,
            "extracted_text": "",
            "ocr_status": "NO_TEXT_FOUND",
            "ocr_confidence": None,
            "character_count": 0,
            "word_count": 0,
            "page_count": 1,
            "error": "No text content found in document.",
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertFalse(res["success"])
        self.assertEqual(res["verdict"], "UNKNOWN")
        self.assertEqual(res["risk_score"], 0)
        self.assertIsNotNone(res["error"])

    def test_ocr_unavailable_status(self):
        ocr_res = {
            "success": False,
            "extracted_text": "",
            "ocr_status": "OCR_UNAVAILABLE",
            "ocr_confidence": None,
            "character_count": 0,
            "word_count": 0,
            "page_count": 1,
            "error": "Image document received, but Tesseract OCR binary is not installed on system PATH.",
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertFalse(res["success"])
        self.assertEqual(res["verdict"], "UNKNOWN")
        self.assertEqual(res["risk_score"], 0)
        self.assertIn("Tesseract OCR", res["error"])


    def test_failed_ocr_status(self):
        ocr_res = {
            "success": False,
            "extracted_text": "",
            "ocr_status": "FAILED",
            "ocr_confidence": None,
            "character_count": 0,
            "word_count": 0,
            "page_count": 0,
            "error": "Empty or corrupted file uploaded.",
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertFalse(res["success"])
        self.assertEqual(res["verdict"], "UNKNOWN")
        self.assertEqual(res["risk_score"], 0)

    def test_risk_score_bounds(self):
        ocr_res = {
            "success": True,
            "extracted_text": "Sample text string for testing boundary metrics.",
            "ocr_status": "SUCCESS",
            "character_count": 48,
        }
        res = analyze_document_extracted_text(ocr_res)

        self.assertGreaterEqual(res["risk_score"], 0)
        self.assertLessEqual(res["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
