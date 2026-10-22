"""
=============================================================================
KAVACH — Safe QR Code Detection & Decoding Service
=============================================================================
Detects, decodes, and analyzes QR codes embedded in uploaded images and PDF
documents using OpenCV's built-in QRCodeDetector and PyMuPDF page rendering.

Security & Stability Features:
  - 100% offline payload extraction (Zero outbound HTTP calls)
  - Supports PNG, JPG, JPEG, BMP, WEBP, and PDF documents
  - Reuses hybrid link scanner (analyze_link_url) for any extracted URLs
  - Identifies embedded payment handles (UPI, Crypto wallet addresses)
  - Computes explainable QR risk scores and threat indicators
=============================================================================
"""

import io
import os
import re
import logging
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
from PIL import Image

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

from app.services.link_scanner import analyze_link_url
from app.services.document_url_extractor import extract_urls_from_text

logger = logging.getLogger("kavach.services.qr_scanner")

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit
SUPPORTED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}

# Regex for financial & crypto schemes
UPI_SCHEME_REGEX = re.compile(r"^upi://pay", re.IGNORECASE)
CRYPTO_SCHEME_REGEX = re.compile(r"^(bitcoin|ethereum|solana|usdt|bitcoincash|litecoin):", re.IGNORECASE)


def load_image_bytes_to_numpy(image_bytes: bytes) -> Optional[np.ndarray]:
    """
    Safely decodes image raw bytes into a BGR numpy array compatible with OpenCV.
    Uses PIL as primary parser to prevent native buffer overflow issues.
    """
    try:
        pil_img = Image.open(io.BytesIO(image_bytes))
        pil_img = pil_img.convert("RGB")
        rgb_array = np.array(pil_img)
        bgr_array = cv2.cvtColor(rgb_array, cv2.COLOR_RGB2BGR)
        return bgr_array
    except Exception as e:
        logger.debug(f"PIL image loading failed: {e}. Trying cv2 imdecode fallback.")

    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        return img_np
    except Exception as e:
        logger.warning(f"Failed to decode image bytes into numpy array: {e}")
        return None


def extract_page_images_from_pdf(pdf_bytes: bytes, max_pages: int = 10) -> List[Tuple[int, np.ndarray]]:
    """
    Renders up to max_pages PDF pages into numpy BGR images using PyMuPDF (fitz).
    Returns list of (page_number_1_indexed, numpy_bgr_array).
    """
    if fitz is None:
        logger.warning("PyMuPDF (fitz) is not installed. PDF QR scanning unavailable.")
        return []

    rendered_pages = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        total_pages = min(len(doc), max_pages)

        for i in range(total_pages):
            page = doc[i]
            # Render page at 150 DPI for accurate QR detection
            pix = page.get_pixmap(dpi=150)
            
            # Convert pixmap to numpy array
            img_data = np.frombuffer(pix.samples, dtype=np.uint8)
            if pix.n == 4:  # RGBA
                img_np = img_data.reshape(pix.height, pix.width, 4)
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGBA2BGR)
            elif pix.n == 3:  # RGB
                img_np = img_data.reshape(pix.height, pix.width, 3)
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
            elif pix.n == 1:  # Grayscale
                img_np = img_data.reshape(pix.height, pix.width)
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_GRAY2BGR)
            else:
                continue

            rendered_pages.append((i + 1, img_bgr))
    except Exception as e:
        logger.error(f"Error rendering PDF pages for QR detection: {e}")

    return rendered_pages


def classify_qr_payload(payload: str) -> Dict[str, Any]:
    """
    Classifies a raw QR payload into payload_type (URL, UPI_PAYMENT, CRYPTO_ADDRESS, PLAIN_TEXT)
    and extracts contained URLs.
    """
    clean_payload = payload.strip()
    
    # Check UPI payment scheme
    if UPI_SCHEME_REGEX.search(clean_payload) or ("pa=" in clean_payload and "pn=" in clean_payload):
        return {
            "payload_type": "UPI_PAYMENT",
            "clean_payload": clean_payload,
            "extracted_urls": []
        }

    # Check Crypto scheme
    if CRYPTO_SCHEME_REGEX.search(clean_payload):
        return {
            "payload_type": "CRYPTO_ADDRESS",
            "clean_payload": clean_payload,
            "extracted_urls": []
        }

    # Check URLs using extract_urls_from_text or prefix inspection
    extractor_res = extract_urls_from_text(clean_payload)
    extracted_urls = [u["url"] for u in extractor_res.get("urls", [])]
    if not extracted_urls and (clean_payload.startswith("http://") or clean_payload.startswith("https://") or clean_payload.startswith("www.")):
        extracted_urls = [clean_payload]

    if extracted_urls:
        return {
            "payload_type": "URL",
            "clean_payload": clean_payload,
            "extracted_urls": extracted_urls
        }

    return {
        "payload_type": "PLAIN_TEXT",
        "clean_payload": clean_payload,
        "extracted_urls": []
    }


def detect_qr_codes_in_image(img_bgr: np.ndarray, page_num: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Detects and decodes QR codes in a single BGR image array using OpenCV's QRCodeDetector.
    Employs ArUco marker-based QR detection and image preprocessing fallbacks for maximum resilience.
    """
    if img_bgr is None or img_bgr.size == 0:
        return []

    detected_payloads: List[str] = []

    # 1. Try OpenCV QRCodeDetectorAruco if available (handles noisy/tilted/complex QR codes)
    if hasattr(cv2, "QRCodeDetectorAruco"):
        try:
            aruco_det = cv2.QRCodeDetectorAruco()
            retval, decoded_info, _, _ = aruco_det.detectAndDecodeMulti(img_bgr)
            if retval and decoded_info:
                for info in decoded_info:
                    if info and info.strip():
                        detected_payloads.append(info.strip())
        except Exception as e:
            logger.debug(f"QRCodeDetectorAruco multi failed: {e}")

    # 2. Try standard QRCodeDetector multi-detection
    if not detected_payloads:
        try:
            detector = cv2.QRCodeDetector()
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(img_bgr)
            if retval and decoded_info:
                for info in decoded_info:
                    if info and info.strip():
                        detected_payloads.append(info.strip())
        except Exception as e:
            logger.debug(f"OpenCV detectAndDecodeMulti failed: {e}")

    # 3. Fallback to single QR detection
    if not detected_payloads:
        try:
            detector = cv2.QRCodeDetector()
            retval, info, _ = detector.detectAndDecode(img_bgr)
            if retval and info and info.strip():
                detected_payloads.append(info.strip())
        except Exception as e:
            logger.debug(f"OpenCV detectAndDecode failed: {e}")

    # 4. Fallback: try grayscale and adaptive thresholding if not detected
    if not detected_payloads:
        try:
            gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
            detector = cv2.QRCodeDetector()
            retval, info, _ = detector.detectAndDecode(gray)
            if retval and info and info.strip():
                detected_payloads.append(info.strip())
            else:
                # Try Otsu threshold
                _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                retval, info_th, _ = detector.detectAndDecode(thresh)
                if retval and info_th and info_th.strip():
                    detected_payloads.append(info_th.strip())
        except Exception as e:
            logger.debug(f"OpenCV grayscale QR fallback failed: {e}")

    # Deduplicate payloads for this image
    unique_payloads = list(dict.fromkeys(detected_payloads))
    qr_results = []

    for payload in unique_payloads:
        classification = classify_qr_payload(payload)
        payload_type = classification["payload_type"]
        clean_payload = classification["clean_payload"]
        urls = classification["extracted_urls"]

        qr_risk_score = 0.0
        threat_indicators = []
        reasons = []
        url_analysis_result = None

        if payload_type == "URL" and urls:
            # Run extracted URL through hybrid URL scanner
            primary_url = urls[0]
            url_analysis_result = analyze_link_url(primary_url)
            qr_risk_score = float(url_analysis_result.get("risk_score", 0.0))
            
            for ind in url_analysis_result.get("detected_indicators", []):
                threat_indicators.append(f"QR URL Indicator: {ind}")
            
            if url_analysis_result.get("risk_level") in ["HIGH_RISK", "SUSPICIOUS"]:
                reasons.append(f"QR code contains risky URL '{primary_url}' ({url_analysis_result.get('risk_level')}).")

        elif payload_type == "UPI_PAYMENT":
            qr_risk_score = 65.0
            threat_indicators.append("Embedded Payment / UPI QR Code Detected")
            reasons.append(f"QR code contains direct UPI payment transfer payload: {clean_payload[:60]}")

        elif payload_type == "CRYPTO_ADDRESS":
            qr_risk_score = 60.0
            threat_indicators.append("Embedded Cryptocurrency Payment QR Code")
            reasons.append(f"QR code contains cryptocurrency wallet address payload: {clean_payload[:60]}")

        else:
            qr_risk_score = 0.0
            reasons.append("QR code contains plain text payload with no immediate security threat detected.")

        qr_item = {
            "payload": clean_payload,
            "payload_type": payload_type,
            "page_number": page_num,
            "url_analysis": url_analysis_result,
            "risk_score": qr_risk_score,
            "threat_indicators": threat_indicators,
            "reasons": reasons
        }
        qr_results.append(qr_item)

    return qr_results


def scan_qr_codes(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Main entrypoint for scanning QR codes in images or PDF files.

    Returns:
        {
            "qr_found": bool,
            "qr_count": int,
            "qr_codes": list[dict],
            "highest_qr_risk_score": float,
            "qr_verdict": "SAFE" | "SUSPICIOUS" | "HIGH_RISK",
            "threat_indicators": list[str],
            "reasons": list[str]
        }
    """
    if not file_bytes:
        return {
            "qr_found": False,
            "qr_count": 0,
            "qr_codes": [],
            "highest_qr_risk_score": 0.0,
            "qr_verdict": "SAFE",
            "threat_indicators": [],
            "reasons": ["No file content provided for QR code scanning."]
        }

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        return {
            "qr_found": False,
            "qr_count": 0,
            "qr_codes": [],
            "highest_qr_risk_score": 75.0,
            "qr_verdict": "HIGH_RISK",
            "threat_indicators": ["Excessive File Size Limit Exceeded"],
            "reasons": ["File size exceeds maximum threshold (10 MB). QR scan skipped."]
        }

    ext = os.path.splitext(filename)[1].lower()
    all_qr_items: List[Dict[str, Any]] = []

    if ext in SUPPORTED_IMAGE_EXTS:
        img_bgr = load_image_bytes_to_numpy(file_bytes)
        if img_bgr is not None:
            all_qr_items = detect_qr_codes_in_image(img_bgr, page_num=None)

    elif ext == ".pdf":
        page_images = extract_page_images_from_pdf(file_bytes, max_pages=10)
        for page_num, img_bgr in page_images:
            qrs = detect_qr_codes_in_image(img_bgr, page_num=page_num)
            all_qr_items.extend(qrs)

    # Compute overall QR assessment metrics
    qr_count = len(all_qr_items)
    qr_found = qr_count > 0

    highest_risk_score = 0.0
    combined_indicators: List[str] = []
    combined_reasons: List[str] = []

    for item in all_qr_items:
        score = item["risk_score"]
        if score > highest_risk_score:
            highest_risk_score = score
        
        for ind in item["threat_indicators"]:
            if ind not in combined_indicators:
                combined_indicators.append(ind)
                
        for rsn in item["reasons"]:
            if rsn not in combined_reasons:
                combined_reasons.append(rsn)

    if not qr_found:
        qr_verdict = "SAFE"
        combined_reasons = ["No QR codes detected in uploaded document or image."]
    elif highest_risk_score >= 70.0:
        qr_verdict = "HIGH_RISK"
    elif highest_risk_score >= 40.0:
        qr_verdict = "SUSPICIOUS"
    else:
        qr_verdict = "SAFE"
        if not combined_reasons:
            combined_reasons = ["QR codes detected contain safe text payloads."]

    return {
        "qr_found": qr_found,
        "qr_count": qr_count,
        "qr_codes": all_qr_items,
        "highest_qr_risk_score": round(highest_risk_score, 2),
        "qr_verdict": qr_verdict,
        "threat_indicators": combined_indicators,
        "reasons": combined_reasons
    }
