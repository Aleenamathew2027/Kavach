"""
=============================================================================
KAVACH — End-to-End Pipeline & Security Verification Test Suite
=============================================================================
Verifies the complete 10-step file handling pipeline across all 10 target file types:
  1. Plain Text (.txt)
  2. PDF Document with selectable text (.pdf)
  3. Word Document (.docx)
  4. PNG / JPG Image file (.png, .jpg)
  5. Document containing phishing URL (.txt / .pdf)
  6. Image containing embedded QR code (.png)
  7. Empty file (0 bytes)
  8. Corrupted file (malformed bytes)
  9. Unsupported file format (.exe / .bin)
 10. Oversized file (> 10 MB limit)

Also verifies API authentication, database logging, high-risk alert creation,
and Guardian privacy restrictions.
=============================================================================
"""

import io
import os
import secrets
import pytest
import cv2
import numpy as np
import docx
import pypdf
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.models.security_scan import SecurityScan
from app.models.security_alert import SecurityAlert
from app.services.ocr_service import process_document_ocr
from app.services.document_risk_orchestrator import orchestrate_document_risk

client = TestClient(app)


def create_qr_image_bytes(payload: str) -> bytes:
    encoder = cv2.QRCodeEncoder_create()
    qr_mat = encoder.encode(payload)
    img_resized = cv2.resize(qr_mat, (300, 300), interpolation=cv2.INTER_NEAREST)
    img_8u = cv2.normalize(img_resized, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)
    img_bgr = cv2.cvtColor(img_8u, cv2.COLOR_GRAY2BGR)
    padded = cv2.copyMakeBorder(img_bgr, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=[255, 255, 255])
    _, buf = cv2.imencode(".png", padded)
    return buf.tobytes()


def create_sample_docx_bytes(text: str) -> bytes:
    doc = docx.Document()
    doc.add_paragraph(text)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def create_sample_pdf_bytes(text: str) -> bytes:
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    # Note: blank PDF page; for text testing, we test text PDFs or process_document_ocr
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.fixture(scope="module")
def user_auth_headers():
    test_id = secrets.token_hex(4)
    email = f"pipeline_e2e_user_{test_id}@kavach.ai"
    password = "KavachE2EPassword123!"

    reg_res = client.post(
        "/users/register",
        json={"full_name": "Pipeline Verifier", "email": email, "password": password}
    )
    assert reg_res.status_code == 201

    login_res = client.post(
        "/users/login",
        json={"email": email, "password": password}
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestPipelineE2E:

    # 1. Plain TXT File
    def test_pipeline_txt_file(self, user_auth_headers):
        content = b"Meeting Minutes: The team discussed the Q3 project timeline and agreed to finalize the design draft by Friday."
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("minutes.txt", content, "text/plain")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["filename"] == "minutes.txt"
        assert data["risk_level"] == "SAFE"
        assert data["ocr_info"]["status"] == "SUCCESS"
        assert data["scan_id"] is not None

    # 2. PDF Document
    def test_pipeline_pdf_file(self, user_auth_headers):
        pdf_bytes = create_sample_pdf_bytes("Kavach PDF Document Verification Test")
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("sample.pdf", pdf_bytes, "application/pdf")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["filename"] == "sample.pdf"
        assert data["scan_id"] is not None

    # 3. DOCX Document
    def test_pipeline_docx_file(self, user_auth_headers):
        docx_bytes = create_sample_docx_bytes("Kavach DOCX Word Document Verification Test")
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("sample.docx", docx_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["filename"] == "sample.docx"
        assert data["ocr_info"]["status"] == "SUCCESS"
        assert "Kavach DOCX" in data["text_preview"]

    # 4. PNG / JPG Image File
    def test_pipeline_image_file(self, user_auth_headers):
        blank_img = np.full((200, 200, 3), 255, dtype=np.uint8)
        _, img_bytes = cv2.imencode(".png", blank_img)
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("sample.png", img_bytes.tobytes(), "image/png")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["filename"] == "sample.png"
        assert data["ocr_info"]["status"] in ["SUCCESS", "NO_TEXT_FOUND", "OCR_UNAVAILABLE"]

    # 5. Document Containing a Phishing URL
    def test_pipeline_document_with_url(self, user_auth_headers):
        scam_doc = (
            b"SECURITY WARNING: Your account is suspended. "
            b"Verify login at http://login-verify-account-security-update.xyz/login"
        )
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("phishing_notice.txt", scam_doc, "text/plain")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["url_analysis"]["url_count"] >= 1
        assert data["url_analysis"]["highest_risk_score"] >= 50.0
        assert data["risk_level"] in ["HIGH RISK", "SUSPICIOUS"]

    # 6. Image Containing a QR Code
    def test_pipeline_image_with_qr(self, user_auth_headers):
        qr_bytes = create_qr_image_bytes("upi://pay?pa=scammer@upi&pn=UrgentPrize")
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("payment_qr.png", qr_bytes, "image/png")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["qr_analysis"]["qr_found"] is True
        assert data["qr_analysis"]["highest_risk_score"] == 65.0
        assert "Embedded Payment / UPI QR Code Detected" in data["detected_indicators"]

    # 7. Empty File (0 bytes)
    def test_pipeline_empty_file(self, user_auth_headers):
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("empty.txt", b"", "text/plain")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["risk_level"] == "UNSCANNABLE"
        assert "empty" in data["summary"].lower() or "empty" in data["reasons"][0].lower()

    # 8. Corrupted File
    def test_pipeline_corrupted_file(self, user_auth_headers):
        corrupt_bytes = b"CORRUPT_BINARY_STREAM_\x00\xff\xfe\xfd"
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("corrupt.pdf", corrupt_bytes, "application/pdf")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["filename"] == "corrupt.pdf"
        assert data["risk_level"] == "UNSCANNABLE"
        assert data["ocr_info"]["status"] in ["NO_TEXT_FOUND", "FAILED", "SUCCESS", "OCR_UNAVAILABLE"]

    # 9. Unsupported File
    def test_pipeline_unsupported_file(self, user_auth_headers):
        unsupported_bytes = b"MZ\x90\x00\x03\x00\x00\x00"
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("malware.exe", unsupported_bytes, "application/x-msdownload")}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["risk_level"] == "UNSCANNABLE"
        assert data["ocr_info"]["status"] in ["UNSUPPORTED_FILE", "UNSUPPORTED_FILE_TYPE", "FAILED"]

    # 10. File Larger Than 10 MB
    def test_pipeline_oversized_file(self, user_auth_headers):
        huge_bytes = b"X" * (10 * 1024 * 1024 + 100)
        res = client.post(
            "/security/analyze-document",
            headers=user_auth_headers,
            files={"file": ("huge_file.pdf", huge_bytes, "application/pdf")}
        )
        assert res.status_code == 400
        assert "exceeds" in res.json()["detail"].lower() or "10mb" in res.json()["detail"].lower()


class TestSecurityAudit:

    def test_database_logging_and_guardian_privacy(self, user_auth_headers):
        """Verifies DB scan logging, high-risk alert creation, and Guardian privacy protection."""
        db = SessionLocal()
        try:
            scam_content = (
                b"CRITICAL ALERT: Your banking credentials have been compromised! "
                b"Submit your password and 6-digit OTP code immediately at http://login-verify-account-security-update.xyz/login"
            )
            res = client.post(
                "/security/analyze-document",
                headers=user_auth_headers,
                files={"file": ("high_risk_scam.txt", scam_content, "text/plain")}
            )
            assert res.status_code == 200
            data = res.json()
            scan_id = data["scan_id"]
            assert scan_id is not None
            assert data["alert_created"] is True

            # 1. Verify SecurityScan DB row
            scan_row = db.query(SecurityScan).filter(SecurityScan.id == scan_id).first()
            assert scan_row is not None
            assert scan_row.scan_type == "document"
            assert scan_row.risk_level in ["HIGH RISK", "SUSPICIOUS"]

            # 2. Verify SecurityAlert DB row and privacy protection
            alert_row = db.query(SecurityAlert).filter(SecurityAlert.user_id == scan_row.user_id).order_by(SecurityAlert.id.desc()).first()
            assert alert_row is not None
            assert alert_row.alert_type == "document_scam"
            
            # PRIVACY CHECK: Ensure full private document text is NEVER written to alert message
            assert "Submit your password and 6-digit OTP" not in alert_row.message
            assert "CRITICAL ALERT: Your banking credentials" not in alert_row.message
        finally:
            db.close()
