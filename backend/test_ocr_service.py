"""
=============================================================================
KAVACH — OCR Service Unit & Integration Test Suite
=============================================================================
Tests safe text extraction across PDF, DOCX, TXT, and image files.
Verifies file size limits, unsupported file handling, OCR status codes,
character/word counts, and missing Tesseract binary fallbacks.
=============================================================================
"""

import os
import io
import unittest
from unittest.mock import patch

import pypdf
import docx
from PIL import Image, ImageDraw

from app.services.ocr_service import process_document_ocr, check_tesseract_availability


class TestOCRService(unittest.TestCase):

    def setUp(self):
        # Create sample plain text PDF bytes in memory
        pdf_writer = pypdf.PdfWriter()
        page = pdf_writer.add_blank_page(width=612, height=792)
        # Note: pypdf doesn't easily write arbitrary text on blank pages, so we use fitz or docx for text
        pass

    def test_plain_text_txt_file(self):
        content = "URGENT SECURITY ALERT: Please verify your bank account credentials immediately."
        file_bytes = content.encode("utf-8")
        res = process_document_ocr(file_bytes, "notice.txt")

        self.assertTrue(res["success"])
        self.assertEqual(res["ocr_status"], "SUCCESS")
        self.assertIn("URGENT SECURITY ALERT", res["extracted_text"])
        self.assertEqual(res["character_count"], len(content))
        self.assertEqual(res["word_count"], len(content.split()))
        self.assertEqual(res["page_count"], 1)

    def test_docx_file_extraction(self):
        doc = docx.Document()
        doc.add_paragraph("Official Invoice Notification")
        doc.add_paragraph("Please remit payment of $500 to account 12345.")
        buf = io.BytesIO()
        doc.save(buf)
        file_bytes = buf.getvalue()

        res = process_document_ocr(file_bytes, "invoice.docx")

        self.assertTrue(res["success"])
        self.assertEqual(res["ocr_status"], "SUCCESS")
        self.assertIn("Official Invoice Notification", res["extracted_text"])
        self.assertGreater(res["word_count"], 5)

    def test_unsupported_file_type(self):
        file_bytes = b"MZ\x90\x00\x03\x00\x00\x00"
        res = process_document_ocr(file_bytes, "malicious_file.exe")

        self.assertFalse(res["success"])
        self.assertEqual(res["ocr_status"], "UNSUPPORTED_FILE")
        self.assertIn("Unsupported file extension", res["error"])

    def test_file_larger_than_10mb(self):
        # 10MB + 100 bytes
        oversized_bytes = b"A" * (10 * 1024 * 1024 + 100)
        res = process_document_ocr(oversized_bytes, "large_document.pdf")

        self.assertFalse(res["success"])
        self.assertEqual(res["ocr_status"], "FILE_TOO_LARGE")
        self.assertIn("10 MB", res["error"])

    def test_empty_corrupted_file(self):
        res = process_document_ocr(b"", "empty.pdf")

        self.assertFalse(res["success"])
        self.assertEqual(res["ocr_status"], "FAILED")
        self.assertIn("Empty or corrupted", res["error"])

    def test_image_ocr_handling_missing_tesseract_fallback(self):
        # Create a synthetic 200x100 white PNG image
        img = Image.new("RGB", (200, 100), color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_bytes = buf.getvalue()

        tess_available, _ = check_tesseract_availability()

        if not tess_available:
            # Verify graceful OCR_UNAVAILABLE status when binary is missing
            res = process_document_ocr(img_bytes, "screenshot.png")
            self.assertFalse(res["success"])
            self.assertEqual(res["ocr_status"], "OCR_UNAVAILABLE")
            self.assertIn("Tesseract OCR binary is not installed", res["error"])
        else:
            # If tesseract is present on environment
            res = process_document_ocr(img_bytes, "screenshot.png")
            self.assertTrue(res["success"])
            self.assertIn(res["ocr_status"], ["SUCCESS", "NO_TEXT_FOUND"])

    @patch("app.services.ocr_service.check_tesseract_availability")
    def test_mocked_ocr_unavailable_status(self, mock_tess):
        mock_tess.return_value = (False, None)
        img = Image.new("RGB", (100, 100), color="white")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")

        res = process_document_ocr(buf.getvalue(), "scan.jpg")

        self.assertFalse(res["success"])
        self.assertEqual(res["ocr_status"], "OCR_UNAVAILABLE")

    def test_no_text_found_txt_file(self):
        res = process_document_ocr(b"   \n\n\t ", "blank.txt")

        self.assertTrue(res["success"])
        self.assertEqual(res["ocr_status"], "NO_TEXT_FOUND")
        self.assertEqual(res["character_count"], 0)
        self.assertEqual(res["word_count"], 0)

    def test_correct_character_and_word_counts(self):
        text = "Quick brown fox jumps over the lazy dog"
        res = process_document_ocr(text.encode("utf-8"), "test.txt")

        self.assertEqual(res["character_count"], len(text))
        self.assertEqual(res["word_count"], 8)



if __name__ == "__main__":
    unittest.main()
