"""
=============================================================================
KAVACH — Document & Image Scanner Multi-Engine Logic Tests
=============================================================================
Tests:
  1. Readable image with suspicious text (OCR mocked)
  2. Image with no text but QR code
  3. Image with suspicious URL text
  4. Image where OCR is unavailable (unmocked or mocked)
  5. Unsupported file format
  6. Safe document (.txt / .docx / .pdf)
  7. High-risk document
  8. QR containing a suspicious URL
  9. QR containing non-URL payload (UPI / plain text)
 10. OCR failure while another detector still succeeds
=============================================================================
"""

import io
import cv2
import numpy as np
import pytest
from unittest.mock import patch
from PIL import Image

from app.services.document_risk_orchestrator import orchestrate_document_risk


def create_qr_image_bytes(payload: str) -> bytes:
    """Helper to generate a clean, readable QR code image buffer."""
    encoder = cv2.QRCodeEncoder_create()
    qr_mat = encoder.encode(payload)
    img_resized = cv2.resize(qr_mat, (300, 300), interpolation=cv2.INTER_NEAREST)
    img_8u = cv2.normalize(img_resized, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)
    img_bgr = cv2.cvtColor(img_8u, cv2.COLOR_GRAY2BGR)
    padded = cv2.copyMakeBorder(img_bgr, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=[255, 255, 255])
    _, buf = cv2.imencode(".png", padded)
    return buf.tobytes()


class TestDocumentScannerMultiEngineFix:

    # 1. Readable image with suspicious text
    @patch("app.services.document_risk_orchestrator.process_document_ocr")
    def test_01_readable_image_with_suspicious_text(self, mock_ocr):
        mock_ocr.return_value = {
            "success": True,
            "ocr_status": "SUCCESS",
            "extracted_text": "URGENT FRAUD ALERT: Your bank account is locked! Send password and OTP immediately to claim $5000 prize or face legal arrest.",
            "character_count": 120,
            "word_count": 22,
            "page_count": 1,
            "error": None,
        }
        res = orchestrate_document_risk(b"DUMMY_IMAGE_BYTES", "scam_screenshot.png")
        assert res["risk_level"] in ["HIGH RISK", "SUSPICIOUS"]
        assert res["risk_score"] >= 50
        assert res["text_analysis"]["verdict"] in ["HIGH_RISK", "SUSPICIOUS"]
        assert len(res["detected_indicators"]) > 0

    # 2. Image with no text but QR code
    def test_02_image_with_no_text_but_qr_code(self):
        qr_bytes = create_qr_image_bytes("Hello from safe plain text QR")
        res = orchestrate_document_risk(qr_bytes, "plain_qr.png")
        assert res["risk_level"] != "UNSCANNABLE"
        assert res["risk_level"] == "SAFE"
        assert res["qr_analysis"]["qr_found"] is True
        assert res["qr_analysis"]["qr_codes"][0]["payload_type"] == "PLAIN_TEXT"

    # 3. Image with suspicious URL text
    @patch("app.services.document_risk_orchestrator.process_document_ocr")
    def test_03_image_with_suspicious_url_text(self, mock_ocr):
        mock_ocr.return_value = {
            "success": True,
            "ocr_status": "SUCCESS",
            "extracted_text": "Please verify your account login at http://security-update-account-verification.xyz/login immediately.",
            "character_count": 105,
            "word_count": 10,
            "page_count": 1,
            "error": None,
        }
        res = orchestrate_document_risk(b"DUMMY_IMAGE_BYTES", "link_screenshot.jpg")
        assert res["url_analysis"]["url_count"] >= 1
        assert res["url_analysis"]["highest_risk_score"] >= 50
        assert res["risk_level"] in ["HIGH RISK", "SUSPICIOUS"]

    # 4. Image where OCR is unavailable
    @patch("app.services.document_risk_orchestrator.process_document_ocr")
    def test_04_image_where_ocr_is_unavailable(self, mock_ocr):
        mock_ocr.return_value = {
            "success": False,
            "ocr_status": "OCR_UNAVAILABLE",
            "extracted_text": "",
            "character_count": 0,
            "word_count": 0,
            "page_count": 1,
            "error": "Tesseract OCR binary not installed on system PATH.",
        }
        # Blank image without QR
        blank_img = np.full((100, 100, 3), 255, dtype=np.uint8)
        _, img_bytes = cv2.imencode(".png", blank_img)
        res = orchestrate_document_risk(img_bytes.tobytes(), "blank_no_tess.png")

        assert res["risk_level"] == "UNSCANNABLE"
        assert res["risk_score"] == 0
        assert res["ocr_info"]["status"] == "OCR_UNAVAILABLE"
        assert res["text_analysis"]["verdict"] == "OCR_UNAVAILABLE"
        assert any("OCR" in r for r in res["reasons"])

    # 5. Unsupported file format
    def test_05_unsupported_file(self):
        res = orchestrate_document_risk(b"MZ\x90\x00executable_bytes", "malware.exe")
        assert res["risk_level"] == "UNSCANNABLE"
        assert res["ocr_info"]["status"] == "UNSUPPORTED_FILE"
        assert "unsupported" in res["summary"].lower()

    # 6. Safe document (.txt / .docx / .pdf)
    def test_06_safe_document(self):
        clean_text = b"Team sync scheduled for Monday at 10:00 AM in Meeting Room A to discuss project milestones."
        res = orchestrate_document_risk(clean_text, "safe_memo.txt")
        assert res["risk_level"] == "SAFE"
        assert res["risk_score"] < 40
        assert res["text_analysis"]["verdict"] == "SAFE"
        assert res["url_analysis"]["url_count"] == 0
        assert res["qr_analysis"]["qr_found"] is False

    # 7. High-risk document
    def test_07_high_risk_document(self):
        scam_text = (
            b"FINAL NOTICE: Urgent warrant issued for tax fraud. "
            b"Send $1000 gift cards or cryptocurrency immediately to avoid arrest. "
            b"Verify login here: http://secure-irs-tax-settlement-gov-portal.xyz/login"
        )
        res = orchestrate_document_risk(scam_text, "tax_warrant.txt")
        assert res["risk_level"] == "HIGH RISK"
        assert res["risk_score"] >= 70
        assert len(res["detected_indicators"]) > 0

    # 8. QR containing a suspicious URL
    def test_08_qr_containing_suspicious_url(self):
        qr_bytes = create_qr_image_bytes("http://login-verify-account-security-update.xyz/login")
        res = orchestrate_document_risk(qr_bytes, "phishing_qr.png")
        assert res["qr_analysis"]["qr_found"] is True
        assert res["qr_analysis"]["qr_codes"][0]["payload_type"] == "URL"
        assert res["url_analysis"]["url_count"] >= 1
        assert res["url_analysis"]["highest_risk_score"] >= 50
        assert res["risk_level"] in ["HIGH RISK", "SUSPICIOUS"]

    # 9. QR containing non-URL payload (UPI / plain text)
    def test_09_qr_containing_non_url_payload(self):
        qr_bytes = create_qr_image_bytes("upi://pay?pa=scammer@upi&pn=UrgentLottery&am=5000")
        res = orchestrate_document_risk(qr_bytes, "upi_qr.png")
        assert res["qr_analysis"]["qr_found"] is True
        assert res["qr_analysis"]["qr_codes"][0]["payload_type"] == "UPI_PAYMENT"
        assert res["url_analysis"]["url_count"] == 0
        assert res["qr_analysis"]["highest_risk_score"] == 65.0
        assert res["risk_level"] in ["SUSPICIOUS", "HIGH RISK"]

    # 10. OCR failure while another detector still succeeds
    @patch("app.services.document_risk_orchestrator.process_document_ocr")
    def test_10_ocr_failure_while_another_detector_still_succeeds(self, mock_ocr):
        mock_ocr.return_value = {
            "success": False,
            "ocr_status": "FAILED",
            "extracted_text": "",
            "character_count": 0,
            "word_count": 0,
            "page_count": 1,
            "error": "Image decompression failed.",
        }
        qr_bytes = create_qr_image_bytes("upi://pay?pa=recipient@upi&pn=Vendor")
        res = orchestrate_document_risk(qr_bytes, "qr_with_ocr_fail.png")

        # Scan should NOT be discarded as UNSCANNABLE because QR detector succeeded
        assert res["risk_level"] != "UNSCANNABLE"
        assert res["qr_analysis"]["qr_found"] is True
        assert res["risk_level"] in ["SUSPICIOUS", "HIGH RISK", "SAFE"]
