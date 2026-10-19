"""
=============================================================================
KAVACH — Authenticated OCR Pipeline & Image Security Test Suite
=============================================================================
Distinguishes between:
  1. Unit tests with mocked PyTesseract responses (test_unit_mocked_ocr_*)
  2. Unmocked system OCR integration tests (test_integration_real_ocr_*)
     which skip cleanly if Tesseract binary is not installed on system PATH.
=============================================================================
"""

import io
import pytest
import unittest
from unittest.mock import patch

from PIL import Image, ImageDraw
import pypdf

from app.services.ocr_service import process_document_ocr, check_tesseract_availability
from app.services.document_risk_orchestrator import orchestrate_document_risk

# Check system Tesseract availability for test skipping
TESSERACT_AVAILABLE, TESSERACT_PATH = check_tesseract_availability()


def create_sample_text_image_bytes(text: str) -> bytes:
    """Helper function to generate a simple PIL RGB image containing text."""
    img = Image.new("RGB", (500, 150), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 50), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestOCRPipelineFull(unittest.TestCase):

    def test_tesseract_availability_detection(self):
        """Verifies safe Tesseract system path detection."""
        is_available, path = check_tesseract_availability()
        self.assertIsInstance(is_available, bool)
        if is_available:
            self.assertIsNotNone(path)

    # -------------------------------------------------------------------------
    # MOCKED UNIT TESTS (Verify string & risk score pipeline when OCR succeeds)
    # -------------------------------------------------------------------------

    @patch("app.services.ocr_service.pytesseract.image_to_string")
    @patch("app.services.ocr_service.check_tesseract_availability")
    def test_unit_mocked_ocr_safe_text_extraction(self, mock_check, mock_ocr):
        """[UNIT TEST - MOCKED OCR] Tests pipeline when OCR returns safe text."""
        mock_check.return_value = (True, r"C:\Program Files\Tesseract-OCR\tesseract.exe")
        mock_ocr.return_value = "Meeting Minutes: The team discussed project timelines and agreed to finalize design draft."

        img_bytes = create_sample_text_image_bytes("Meeting Minutes...")
        res = orchestrate_document_risk(img_bytes, "minutes_screenshot.png")

        self.assertEqual(res["ocr_info"]["status"], "SUCCESS")
        self.assertEqual(res["risk_level"], "SAFE")
        self.assertLess(res["risk_score"], 40)
        self.assertIn("Meeting Minutes", res["text_preview"])

    @patch("app.services.ocr_service.pytesseract.image_to_string")
    @patch("app.services.ocr_service.check_tesseract_availability")
    def test_unit_mocked_ocr_scam_text_extraction(self, mock_check, mock_ocr):
        """[UNIT TEST - MOCKED OCR] Tests pipeline when OCR returns scam text."""
        mock_check.return_value = (True, r"C:\Program Files\Tesseract-OCR\tesseract.exe")
        mock_ocr.return_value = "URGENT BANK ALERT: Share your 6-digit OTP code and password immediately to prevent account lock!"

        img_bytes = create_sample_text_image_bytes("URGENT BANK ALERT...")
        res = orchestrate_document_risk(img_bytes, "alert_screenshot.jpg")

        self.assertEqual(res["ocr_info"]["status"], "SUCCESS")
        self.assertIn(res["risk_level"], ["HIGH RISK", "SUSPICIOUS"])
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertTrue(len(res["detected_indicators"]) > 0)

    @patch("app.services.ocr_service.check_tesseract_availability")
    def test_unit_mocked_ocr_unavailable_verdict_is_unscannable(self, mock_check):
        """[UNIT TEST - MOCKED OCR] Verifies OCR_UNAVAILABLE status results in UNSCANNABLE verdict."""
        mock_check.return_value = (False, None)
        img_bytes = create_sample_text_image_bytes("Scanned image content")
        res = orchestrate_document_risk(img_bytes, "scanned_doc.png")

        self.assertEqual(res["ocr_info"]["status"], "OCR_UNAVAILABLE")
        self.assertEqual(res["risk_level"], "UNSCANNABLE")
        self.assertIn("This file could not be fully analyzed", res["recommended_action"])

    @patch("app.services.ocr_service.pytesseract.image_to_string")
    @patch("app.services.ocr_service.check_tesseract_availability")
    def test_unit_mocked_blank_image_no_text_found_is_unscannable(self, mock_check, mock_ocr):
        """[UNIT TEST - MOCKED OCR] Verifies blank image returns NO_TEXT_FOUND and UNSCANNABLE verdict."""
        mock_check.return_value = (True, r"C:\Program Files\Tesseract-OCR\tesseract.exe")
        mock_ocr.return_value = ""  # No text detected

        blank_img = Image.new("RGB", (200, 200), color="white")
        buf = io.BytesIO()
        blank_img.save(buf, format="PNG")

        res = orchestrate_document_risk(buf.getvalue(), "blank_image.png")

        self.assertEqual(res["ocr_info"]["status"], "NO_TEXT_FOUND")
        self.assertEqual(res["risk_level"], "UNSCANNABLE")
        self.assertIn("This file could not be fully analyzed", res["recommended_action"])

    # -------------------------------------------------------------------------
    # REAL UNMOCKED INTEGRATION TESTS (Skipped cleanly if Tesseract binary missing)
    # -------------------------------------------------------------------------

    @pytest.mark.skipif(not TESSERACT_AVAILABLE, reason="Tesseract OCR binary is not installed on system PATH")
    def test_integration_real_ocr_image_scan(self):
        """[REAL INTEGRATION TEST] Tests actual Tesseract binary execution on local image."""
        img_bytes = create_sample_text_image_bytes("Real Tesseract Test")
        res = process_document_ocr(img_bytes, "real_test.png")
        self.assertTrue(res["success"])
        self.assertIn(res["ocr_status"], ["SUCCESS", "NO_TEXT_FOUND"])

    @pytest.mark.skipif(TESSERACT_AVAILABLE, reason="Tesseract is installed; testing unmocked missing Tesseract fallback")
    def test_integration_unmocked_missing_tesseract_fallback(self):
        """[REAL INTEGRATION TEST] Confirms missing Tesseract on system yields OCR_UNAVAILABLE and UNSCANNABLE."""
        img_bytes = create_sample_text_image_bytes("Unmocked Image")
        res = orchestrate_document_risk(img_bytes, "unmocked_screenshot.png")
        self.assertEqual(res["ocr_info"]["status"], "OCR_UNAVAILABLE")
        self.assertEqual(res["risk_level"], "UNSCANNABLE")


if __name__ == "__main__":
    unittest.main()
