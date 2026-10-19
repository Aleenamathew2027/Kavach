"""
=============================================================================
KAVACH — Unit Test Suite for Document Risk Orchestrator
=============================================================================
"""

import pytest
import cv2
import numpy as np

from app.services.document_risk_orchestrator import orchestrate_document_risk


def create_qr_image_bytes(payload: str) -> bytes:
    encoder = cv2.QRCodeEncoder_create()
    qr_mat = encoder.encode(payload)
    img_resized = cv2.resize(qr_mat, (300, 300), interpolation=cv2.INTER_NEAREST)
    img_8u = cv2.normalize(img_resized, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)
    img_bgr = cv2.cvtColor(img_8u, cv2.COLOR_GRAY2BGR)
    padded = cv2.copyMakeBorder(img_bgr, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=[255, 255, 255])
    _, buf = cv2.imencode(".png", padded)
    return buf.tobytes()


def test_orchestrator_safe_text_file():
    text_content = b"Meeting Minutes: The team discussed the Q3 project timeline and agreed to finalize the design draft by Friday."
    res = orchestrate_document_risk(text_content, "statement.txt")

    assert res["risk_level"] == "SAFE"
    assert res["risk_score"] < 40
    assert res["ocr_info"]["status"] == "SUCCESS"
    assert res["url_analysis"]["url_count"] == 0
    assert res["qr_analysis"]["qr_found"] is False


def test_orchestrator_phishing_text_and_url():
    scam_text = (
        b"URGENT ALERT: Your bank account is locked! "
        b"Claim $10,000 lottery cash reward immediately. "
        b"Please send your OTP and verify login at http://login-verify-account-security-update.xyz/login"
    )
    res = orchestrate_document_risk(scam_text, "urgent_claim.txt")

    assert res["risk_level"] in ["HIGH RISK", "SUSPICIOUS"]
    assert res["risk_score"] >= 60
    assert len(res["detected_indicators"]) > 0
    assert res["url_analysis"]["url_count"] >= 1
    assert res["url_analysis"]["highest_risk_score"] >= 50.0


def test_orchestrator_upi_qr_code_image():
    qr_bytes = create_qr_image_bytes("upi://pay?pa=scammer@upi&pn=UrgentLottery&am=5000")
    res = orchestrate_document_risk(qr_bytes, "payment_qr.png")

    assert res["qr_analysis"]["qr_found"] is True
    assert res["qr_analysis"]["highest_risk_score"] == 65.0
    assert res["risk_level"] in ["SUSPICIOUS", "HIGH RISK"]
    assert "Embedded Payment / UPI QR Code Detected" in res["detected_indicators"]


def test_orchestrator_oversized_file():
    huge_bytes = b"0" * (10 * 1024 * 1024 + 10)
    res = orchestrate_document_risk(huge_bytes, "large_file.txt")

    assert res["risk_level"] == "HIGH RISK"
    assert res["risk_score"] == 75
    assert "Excessive File Size Limit Exceeded" in res["detected_indicators"]


def test_orchestrator_empty_file():
    res = orchestrate_document_risk(b"", "empty.txt")
    assert res["risk_level"] == "UNSCANNABLE"
    assert res["risk_score"] == 0
    assert "Empty File" in res["detected_indicators"]
    assert "This file could not be fully analyzed" in res["recommended_action"]


def test_orchestrator_unsupported_file():
    res = orchestrate_document_risk(b"MZ\x90\x00\x03\x00", "program.exe")
    assert res["risk_level"] == "UNSCANNABLE"
    assert "This file could not be fully analyzed" in res["recommended_action"]


def test_orchestrator_corrupted_file():
    res = orchestrate_document_risk(b"CORRUPT_BYTES_\x00\xff\xfe", "bad.pdf")
    assert res["risk_level"] == "UNSCANNABLE"
    assert "This file could not be fully analyzed" in res["recommended_action"]
