"""
=============================================================================
KAVACH — Comprehensive Document & Image Scam Risk Orchestrator
=============================================================================
Combines OCR text extraction, Message ML scam analysis, extracted URL hybrid
scanning, and embedded QR code detection into a unified 0-100 risk verdict.

Architectural Workflow:
  1. Safe OCR & Text Extraction (ocr_service)
  2. Message ML Scam & Pattern Analysis (document_text_analyzer)
  3. Extracted URL Identification & Hybrid ML Scanning (document_url_extractor & document_url_analyzer)
  4. OpenCV In-Memory QR Detection & Link/Payment Analysis (qr_scanner)
  5. Dynamic Multi-Engine Risk Score Calculation & Threat Synthesis
=============================================================================
"""

import os
import re
import logging
from typing import Any, Dict, List, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

from app.services.ocr_service import process_document_ocr
from app.services.document_text_analyzer import analyze_document_extracted_text
from app.services.document_url_extractor import extract_urls_from_text
from app.services.document_url_analyzer import analyze_extracted_url_list
from app.services.qr_scanner import scan_qr_codes

logger = logging.getLogger("kavach.services.document_risk_orchestrator")

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit
SUPPORTED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
SUPPORTED_DOC_EXTS = {".pdf", ".docx", ".doc", ".txt"}
ALL_SUPPORTED_EXTS = SUPPORTED_IMAGE_EXTS | SUPPORTED_DOC_EXTS


def determine_file_type(filename: str) -> str:
    """Returns a user-friendly label for the file type based on extension."""
    ext = os.path.splitext(filename or "")[1].lower()
    if ext == ".pdf":
        return "PDF Document"
    elif ext in (".docx", ".doc"):
        return "Word Document"
    elif ext == ".txt":
        return "Text Document"
    elif ext == ".png":
        return "Image (PNG)"
    elif ext in (".jpg", ".jpeg"):
        return "Image (JPEG)"
    elif ext == ".bmp":
        return "Image (BMP)"
    elif ext == ".webp":
        return "Image (WEBP)"
    return "Unsupported Document"


def orchestrate_document_risk(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Main orchestrator for analyzing an uploaded document or image file.

    Evaluates:
      - Text ML scam detector (when text exists)
      - Hybrid URL link analyzer (from text, QR, annotations, or metadata)
      - Independent QR code scanner (for images & PDFs)

    Handles components independently so that single-component unavailability (e.g. OCR)
    does not cause the entire scan to be discarded if another detector succeeds.
    """
    ext = os.path.splitext(filename or "")[1].lower()
    file_type = determine_file_type(filename)

    # 0. Size & File Existence Validation
    if not file_bytes:
        return {
            "filename": filename,
            "file_type": file_type if ext in ALL_SUPPORTED_EXTS else "Unknown",
            "risk_level": "UNSCANNABLE",
            "risk_score": 0,
            "detected_indicators": ["Empty File"],
            "reasons": ["Uploaded file is empty and contains no readable data."],
            "text_preview": "(Empty File)",
            "recommended_action": "This file could not be fully analyzed. Do not trust it without verifying the source.",
            "summary": "Empty file uploaded. Content could not be analyzed.",
            "ocr_info": {"status": "FAILED", "word_count": 0, "character_count": 0, "page_count": 0},
            "text_analysis": {"risk_score": 0, "verdict": "UNSCANNABLE"},
            "url_analysis": {"url_count": 0, "highest_risk_score": 0, "verdict": "UNSCANNABLE", "urls": []},
            "qr_analysis": {"qr_found": False, "qr_count": 0, "highest_risk_score": 0, "verdict": "UNSCANNABLE", "qr_codes": []},
            "threat_breakdown": {"text_risk_score": 0, "url_risk_score": 0, "qr_risk_score": 0, "final_score": 0}
        }

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        return {
            "filename": filename,
            "file_type": file_type,
            "risk_level": "HIGH RISK",
            "risk_score": 75,
            "detected_indicators": ["Excessive File Size Limit Exceeded"],
            "reasons": ["The file size exceeds the safe 10MB scanning threshold."],
            "text_preview": "(File oversized - content skipped)",
            "recommended_action": "Do not upload oversized files. Split or compress the file before scanning.",
            "summary": "File size limit exceeded.",
            "ocr_info": {"status": "FAILED", "word_count": 0, "character_count": 0, "page_count": 0},
            "text_analysis": {"risk_score": 75, "verdict": "HIGH_RISK"},
            "url_analysis": {"url_count": 0, "highest_risk_score": 0, "verdict": "SAFE", "urls": []},
            "qr_analysis": {"qr_found": False, "qr_count": 0, "highest_risk_score": 0, "verdict": "SAFE", "qr_codes": []},
            "threat_breakdown": {"text_risk_score": 75, "url_risk_score": 0, "qr_risk_score": 0, "final_score": 75}
        }

    if ext not in ALL_SUPPORTED_EXTS:
        return {
            "filename": filename,
            "file_type": "Unsupported Document",
            "risk_level": "UNSCANNABLE",
            "risk_score": 0,
            "detected_indicators": ["Unsupported File Format"],
            "reasons": [f"File extension '{ext}' is unsupported. Supported formats: PDF, DOCX, TXT, PNG, JPG, JPEG, BMP, WEBP."],
            "text_preview": "(Unsupported format)",
            "recommended_action": "This file could not be fully analyzed. Do not trust it without verifying the source.",
            "summary": f"Unsupported file extension '{ext}'. Scan skipped.",
            "ocr_info": {"status": "UNSUPPORTED_FILE", "word_count": 0, "character_count": 0, "page_count": 0},
            "text_analysis": {"risk_score": 0, "verdict": "UNSCANNABLE"},
            "url_analysis": {"url_count": 0, "highest_risk_score": 0, "verdict": "UNSCANNABLE", "urls": []},
            "qr_analysis": {"qr_found": False, "qr_count": 0, "highest_risk_score": 0, "verdict": "UNSCANNABLE", "qr_codes": []},
            "threat_breakdown": {"text_risk_score": 0, "url_risk_score": 0, "qr_risk_score": 0, "final_score": 0}
        }

    # 1. OCR & Text Extraction
    ocr_res = process_document_ocr(file_bytes, filename)
    extracted_text = ocr_res.get("extracted_text", "")
    ocr_status = ocr_res.get("ocr_status", "SUCCESS")
    ocr_err = ocr_res.get("error")

    # 2. Text Scam Analysis (Message ML model + rule engine if usable text exists)
    usable_text_exists = bool(extracted_text and extracted_text.strip())

    if usable_text_exists:
        text_analysis = analyze_document_extracted_text(ocr_res)
        text_risk_score = float(text_analysis.get("risk_score", 0.0))
        text_verdict = text_analysis.get("verdict") or text_analysis.get("text_verdict") or "SAFE"
    elif ocr_status == "NO_TEXT_FOUND":
        text_analysis = {
            "success": True,
            "verdict": "NO_TEXT_FOUND",
            "risk_score": 0,
            "confidence": 1.0,
            "scam_probability": 0.0,
            "model": "OCR Text Scanner",
            "indicators": [],
            "reasons": ["No readable text content detected in document or image."],
            "analyzed_character_count": 0,
            "text_preview": ""
        }
        text_risk_score = 0.0
        text_verdict = "NO_TEXT_FOUND"
    elif ocr_status == "OCR_UNAVAILABLE":
        text_analysis = {
            "success": False,
            "verdict": "OCR_UNAVAILABLE",
            "risk_score": 0,
            "confidence": 0.0,
            "scam_probability": 0.0,
            "model": "Unavailable",
            "indicators": [],
            "reasons": ["OCR engine binary (Tesseract) is not available on host. Image text could not be extracted."],
            "analyzed_character_count": 0,
            "text_preview": "",
            "error": ocr_err or "Tesseract OCR binary not installed on system PATH."
        }
        text_risk_score = 0.0
        text_verdict = "OCR_UNAVAILABLE"
    else:
        text_analysis = {
            "success": False,
            "verdict": "UNSCANNABLE",
            "risk_score": 0,
            "confidence": 0.0,
            "scam_probability": 0.0,
            "model": "None",
            "indicators": [],
            "reasons": [ocr_err or f"Text extraction failed (Status: {ocr_status})."],
            "analyzed_character_count": 0,
            "text_preview": "",
            "error": ocr_err
        }
        text_risk_score = 0.0
        text_verdict = "UNSCANNABLE"

    # 3. URL Extraction (Text, PDF Link Annotations, Raw Byte Search)
    raw_url_items: List[Dict[str, str]] = []
    seen_urls = set()

    # (a) URLs extracted from text
    if usable_text_exists:
        text_url_res = extract_urls_from_text(extracted_text)
        for u in text_url_res.get("urls", []):
            u_str = u["url"].strip()
            norm = u_str.rstrip('/')
            if norm and norm not in seen_urls:
                seen_urls.add(norm)
                raw_url_items.append({
                    "url": u_str,
                    "raw_extracted": u.get("raw_extracted", u_str),
                    "source": "document_text"
                })

    # (b) URLs from PDF hyperlink annotations (clickable links even in image-only PDFs)
    if ext == ".pdf" and fitz is not None:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            for page in doc:
                for link in page.get_links():
                    uri = link.get("uri")
                    if uri and uri.strip():
                        u_str = uri.strip()
                        norm = u_str.rstrip('/')
                        if norm and norm not in seen_urls:
                            seen_urls.add(norm)
                            raw_url_items.append({
                                "url": u_str,
                                "raw_extracted": u_str,
                                "source": "pdf_annotation"
                            })
        except Exception as e:
            logger.debug(f"PDF annotation extraction notice: {e}")

    # 4. QR Code Scanner Integration (Independent Detection for Images & PDFs)
    qr_analysis = scan_qr_codes(file_bytes, filename)
    qr_found = qr_analysis.get("qr_found", False)
    qr_risk_score = float(qr_analysis.get("highest_qr_risk_score", 0.0))
    qr_verdict = qr_analysis.get("qr_verdict", "SAFE")
    qr_codes = qr_analysis.get("qr_codes", [])

    # (c) URLs from embedded QR codes
    for qr in qr_codes:
        if qr.get("payload_type") == "URL":
            qr_url = qr.get("payload", "").strip()
            if qr_url:
                norm = qr_url.rstrip('/')
                if norm and norm not in seen_urls:
                    seen_urls.add(norm)
                    raw_url_items.append({
                        "url": qr_url,
                        "raw_extracted": qr_url,
                        "source": "qr_code"
                    })

    # (d) Fallback URL search in raw printable bytes if OCR was unavailable or failed
    if not raw_url_items and not usable_text_exists:
        try:
            raw_matches = re.findall(rb'(?:https?://|www\.)[a-zA-Z0-9_\-\./\?=%&#~:@+]+', file_bytes)
            for m in raw_matches:
                try:
                    candidate = m.decode("ascii", errors="ignore").strip().rstrip(".,;:!?'\")")
                    if len(candidate) > 8 and "." in candidate:
                        norm = candidate.rstrip('/')
                        if norm and norm not in seen_urls:
                            seen_urls.add(norm)
                            raw_url_items.append({
                                "url": candidate,
                                "raw_extracted": candidate,
                                "source": "embedded_metadata"
                            })
                except Exception:
                    continue
        except Exception:
            pass

    # 5. Hybrid Link Scanning on all discovered URLs
    url_analysis = analyze_extracted_url_list(raw_url_items)
    url_risk_score = float(url_analysis.get("highest_url_risk_score", 0.0))
    url_verdict = url_analysis.get("overall_url_verdict", "SAFE")
    url_count = url_analysis.get("url_count", 0)
    has_urls = url_count > 0

    # 6. Multi-Engine Risk Score Orchestration
    active_scores = []
    if usable_text_exists:
        active_scores.append(text_risk_score)
    if has_urls:
        active_scores.append(url_risk_score)
    if qr_found:
        active_scores.append(qr_risk_score)

    if len(active_scores) > 1:
        # Preserve maximum threat vector score while factoring multi-vector weights
        weighted_score = (text_risk_score * 0.45) + (url_risk_score * 0.35) + (qr_risk_score * 0.20)
        overall_score_val = max(weighted_score, *active_scores)
    elif active_scores:
        overall_score_val = active_scores[0]
    else:
        overall_score_val = 0.0

    final_risk_score = min(int(round(overall_score_val)), 100)

    # Determine Verdict cleanly without assigning misleading SAFE to unscannable files
    if final_risk_score >= 70:
        final_risk_level = "HIGH RISK"
    elif final_risk_score >= 40:
        final_risk_level = "SUSPICIOUS"
    elif usable_text_exists or has_urls or qr_found:
        final_risk_level = "SAFE"
    else:
        final_risk_level = "UNSCANNABLE"

    # 7. Synthesize Indicators & Reasons
    combined_indicators: List[str] = []
    combined_reasons: List[str] = []

    # Text indicators
    text_inds = text_analysis.get("indicators") or text_analysis.get("detected_indicators") or []
    for ind in text_inds:
        if ind not in combined_indicators:
            combined_indicators.append(ind)

    # URL indicators & reasons
    for analyzed_url in url_analysis.get("urls", []):
        u_inds = analyzed_url.get("indicators") or analyzed_url.get("detected_indicators") or []
        for ind in u_inds:
            formatted_ind = f"URL Threat: {ind}"
            if formatted_ind not in combined_indicators:
                combined_indicators.append(formatted_ind)
        for rsn in analyzed_url.get("reasons", []):
            if rsn not in combined_reasons:
                combined_reasons.append(rsn)

    # QR indicators & reasons
    for ind in qr_analysis.get("threat_indicators", []):
        if ind not in combined_indicators:
            combined_indicators.append(ind)

    for rsn in text_analysis.get("reasons", []):
        if rsn not in combined_reasons:
            combined_reasons.append(rsn)
    for rsn in qr_analysis.get("reasons", []):
        if rsn not in combined_reasons:
            combined_reasons.append(rsn)

    # If unscannable, formulate clear reason for the failure
    if final_risk_level == "UNSCANNABLE":
        if ocr_status == "OCR_UNAVAILABLE":
            unscannable_reason = (
                "File content could not be analyzed because OCR engine (Tesseract) is unavailable on host, "
                "and no embedded QR codes or URLs were detected."
            )
        elif ocr_status == "UNSUPPORTED_FILE":
            unscannable_reason = ocr_err or f"File format '{ext}' is unsupported."
        elif ocr_status == "FILE_TOO_LARGE":
            unscannable_reason = "File size exceeds maximum allowable limit of 10MB."
        elif ocr_status == "NO_TEXT_FOUND":
            unscannable_reason = "No readable text, URLs, or QR codes were found in this file."
        else:
            unscannable_reason = ocr_err or f"File content could not be reliably analyzed (OCR Status: {ocr_status})."

        if unscannable_reason not in combined_reasons:
            combined_reasons.insert(0, unscannable_reason)

        summary_msg = f"Document could not be reliably analyzed ({unscannable_reason}). Risk Level: UNSCANNABLE."
        recommended_action = "This file could not be fully analyzed. Do not trust it without verifying the source."
    elif final_risk_level == "HIGH RISK":
        recommended_action = (
            "CRITICAL: Do not interact with links, QR codes, or instructions in this document. "
            "It exhibits strong fraudulent scam patterns or dangerous malware links."
        )
        summary_msg = (
            f"Document analyzed via multi-engine scanner. Risk Level: {final_risk_level} "
            f"(Risk Score: {final_risk_score}/100)."
        )
    elif final_risk_level == "SUSPICIOUS":
        recommended_action = (
            "WARNING: Exercise caution. This document contains suspicious language, unverified links, "
            "or payment requests. Verify the sender through official channels before acting."
        )
        summary_msg = (
            f"Document analyzed via multi-engine scanner. Risk Level: {final_risk_level} "
            f"(Risk Score: {final_risk_score}/100)."
        )
    else:
        recommended_action = (
            "No significant scam or phishing threats detected. Ensure document origin is trusted."
        )
        summary_msg = (
            f"Document analyzed via multi-engine scanner. Risk Level: {final_risk_level} "
            f"(Risk Score: {final_risk_score}/100)."
        )

    text_preview = text_analysis.get("text_preview", "")
    if not text_preview and extracted_text:
        text_preview = extracted_text.strip()[:250] + ("…" if len(extracted_text.strip()) > 250 else "")

    return {
        "filename": filename,
        "file_type": file_type,
        "risk_level": final_risk_level,
        "risk_score": final_risk_score,
        "detected_indicators": combined_indicators,
        "reasons": combined_reasons,
        "text_preview": text_preview,
        "recommended_action": recommended_action,
        "summary": summary_msg,
        # Extended Analysis Objects for UI & Audit
        "ocr_info": {
            "status": ocr_status,
            "word_count": ocr_res.get("word_count", 0),
            "character_count": ocr_res.get("character_count", 0),
            "page_count": ocr_res.get("page_count", 1),
            "is_scanned_document": ocr_res.get("is_scanned_document", False)
        },
        "text_analysis": {
            "risk_score": text_risk_score,
            "verdict": text_verdict,
            "ml_prediction": text_analysis.get("ml_prediction"),
            "scam_probability": text_analysis.get("scam_probability"),
            "detected_indicators": text_inds
        },
        "url_analysis": {
            "url_count": url_count,
            "highest_risk_score": url_risk_score,
            "verdict": url_verdict if (has_urls or final_risk_level != "UNSCANNABLE") else "UNSCANNABLE",
            "analyzed_urls": url_analysis.get("urls", [])
        },
        "qr_analysis": {
            "qr_found": qr_found,
            "qr_count": qr_analysis.get("qr_count", 0),
            "highest_risk_score": qr_risk_score,
            "verdict": qr_verdict if (qr_found or final_risk_level != "UNSCANNABLE") else "UNSCANNABLE",
            "qr_codes": qr_codes
        },
        "threat_breakdown": {
            "text_risk_score": text_risk_score,
            "url_risk_score": url_risk_score,
            "qr_risk_score": qr_risk_score,
            "final_score": final_risk_score
        }
    }
