"""
=============================================================================
KAVACH — Unit Test Suite for QR Code Scanning Service (qr_scanner.py)
=============================================================================
"""

import io
import pytest
import cv2
import numpy as np
from PIL import Image

from app.services.qr_scanner import (
    load_image_bytes_to_numpy,
    classify_qr_payload,
    detect_qr_codes_in_image,
    scan_qr_codes
)


def create_synthetic_qr_image_bytes(payload: str) -> bytes:
    """Helper function to generate a valid QR code image as PNG bytes using OpenCV."""
    encoder = cv2.QRCodeEncoder_create()
    qr_mat = encoder.encode(payload)
    # Resize with nearest neighbor for sharp pixel boundaries
    img_resized = cv2.resize(qr_mat, (300, 300), interpolation=cv2.INTER_NEAREST)
    img_8u = cv2.normalize(img_resized, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)
    img_bgr = cv2.cvtColor(img_8u, cv2.COLOR_GRAY2BGR)
    
    # Add quiet zone padding (white border)
    padded = cv2.copyMakeBorder(img_bgr, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=[255, 255, 255])
    
    is_success, buffer = cv2.imencode(".png", padded)
    if is_success:
        return buffer.tobytes()
    
    # Fallback with PIL
    pil_img = Image.fromarray(cv2.cvtColor(padded, cv2.COLOR_BGR2RGB))
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    return buf.getvalue()


def test_load_image_bytes_to_numpy_valid():
    img_bytes = create_synthetic_qr_image_bytes("https://kavach-security.org")
    numpy_arr = load_image_bytes_to_numpy(img_bytes)
    assert numpy_arr is not None
    assert isinstance(numpy_arr, np.ndarray)
    assert numpy_arr.ndim == 3


def test_load_image_bytes_to_numpy_corrupt():
    corrupt_bytes = b"NOT_AN_IMAGE_DATA_12345"
    res = load_image_bytes_to_numpy(corrupt_bytes)
    assert res is None


def test_classify_qr_payload():
    # URL classification
    res_url = classify_qr_payload("https://verify-bank-login-secure.com")
    assert res_url["payload_type"] == "URL"
    assert "https://verify-bank-login-secure.com" in res_url["extracted_urls"]

    # UPI classification
    res_upi = classify_qr_payload("upi://pay?pa=scammer@upi&pn=FraudPay&am=5000")
    assert res_upi["payload_type"] == "UPI_PAYMENT"

    # Crypto classification
    res_crypto = classify_qr_payload("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert res_crypto["payload_type"] == "CRYPTO_ADDRESS"

    # Plain text classification
    res_text = classify_qr_payload("Invoice #9823 - Safe Document")
    assert res_text["payload_type"] == "PLAIN_TEXT"


def test_scan_qr_codes_no_qr_blank_image():
    # Create blank white image
    blank = np.full((300, 300, 3), 255, dtype=np.uint8)
    _, buf = cv2.imencode(".png", blank)
    
    res = scan_qr_codes(buf.tobytes(), "blank.png")
    assert res["qr_found"] is False
    assert res["qr_count"] == 0
    assert res["highest_qr_risk_score"] == 0.0
    assert res["qr_verdict"] == "SAFE"


def test_scan_qr_codes_upi_payment_qr():
    qr_bytes = create_synthetic_qr_image_bytes("upi://pay?pa=quickmoney@upi&pn=UrgentPrize")
    res = scan_qr_codes(qr_bytes, "payment_qr.png")
    
    assert res["qr_found"] is True
    assert res["qr_count"] >= 1
    assert res["qr_codes"][0]["payload_type"] == "UPI_PAYMENT"
    assert res["highest_qr_risk_score"] == 65.0
    assert res["qr_verdict"] == "SUSPICIOUS"
    assert "Embedded Payment / UPI QR Code Detected" in res["threat_indicators"]


def test_scan_qr_codes_phishing_url_qr():
    qr_bytes = create_synthetic_qr_image_bytes("http://login-verify-account-security-update.xyz/login")
    res = scan_qr_codes(qr_bytes, "phishing_qr.png")

    assert res["qr_found"] is True
    assert res["qr_codes"][0]["payload_type"] == "URL"
    assert res["qr_codes"][0]["url_analysis"] is not None
    assert res["highest_qr_risk_score"] >= 50.0
    assert res["qr_verdict"] in ["SUSPICIOUS", "HIGH_RISK"]


def test_scan_qr_codes_oversized_file():
    huge_bytes = b"X" * (10 * 1024 * 1024 + 1)
    res = scan_qr_codes(huge_bytes, "oversized.png")
    assert res["qr_found"] is False
    assert res["qr_verdict"] == "HIGH_RISK"
    assert "Excessive File Size Limit Exceeded" in res["threat_indicators"]
