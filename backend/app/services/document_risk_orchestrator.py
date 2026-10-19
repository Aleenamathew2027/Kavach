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
import logging
from typing import Any, Dict, List, Optional

from app.services.ocr_service import process_document_ocr
from app.services.document_text_analyzer import analyze_document_extracted_text
from app.services.document_url_extractor import extract_urls_from_text
from app.services.document_url_analyzer import analyze_extracted_url_list
from app.services.qr_scanner import scan_qr_codes

logger = logging.getLogger("kavach.services.document_risk_orchestrator")

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit


def orchestrate_document_risk(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Main orchestrator for analyzing an uploaded document or image file.

    Returns a comprehensive result dictionary containing overall risk verdict,
    score, threat indicators, preview, guidance, and detailed sub-analysis.
    """
    # 0. Size Validation
    if not file_bytes:
        return {
            "filename": filename,
            "file_type": "Unknown",
            "risk_level": "UNSCANNABLE",
            "risk_score": 0,
            "detected_indicators": ["Empty File"],
            "reasons": ["Uploaded file is empty and contains no readable data."],
            "text_preview": "(Empty File)",
            "recommended_action": "This file could not be fully analyzed. Do not trust it without verifying the source.",
            "summary": "Empty file uploaded. Content could not be analyzed.",
            "ocr_info": {"status": "FAILED", "word_count": 0, "character_count": 0, "page_count": 0},
            "text_analysis": {"risk_score": 0, "verdict": "UNSCANNABLE"},
            "url_analysis": {"url_count": 0, "highest_risk_score": 0, "verdict": "UNSCANNABLE"},
            "qr_analysis": {"qr_found": False, "qr_count": 0, "highest_risk_score": 0, "verdict": "UNSCANNABLE"},
            "threat_breakdown": {"text_risk_score": 0, "url_risk_score": 0, "qr_risk_score": 0, "final_score": 0}
        }

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        return {
            "filename": filename,
            "file_type": "Unknown",
            "risk_level": "HIGH RISK",
            "risk_score": 75,
            "detected_indicators": ["Excessive File Size Limit Exceeded"],
            "reasons": ["The file size exceeds the safe 10MB scanning threshold."],
            "text_preview": "(File oversized - content skipped)",
            "recommended_action": "Do not upload oversized files. Split or compress the file before scanning.",
            "summary": "File size limit exceeded.",
            "ocr_info": {"status": "FAILED", "word_count": 0, "character_count": 0, "page_count": 0},
            "text_analysis": {"risk_score": 75, "verdict": "HIGH_RISK"},
            "url_analysis": {"url_count": 0, "highest_risk_score": 0, "verdict": "SAFE"},
            "qr_analysis": {"qr_found": False, "qr_count": 0, "highest_risk_score": 0, "verdict": "SAFE"},
            "threat_breakdown": {"text_risk_score": 75, "url_risk_score": 0, "qr_risk_score": 0, "final_score": 75}
        }

    # 1. OCR & Text Extraction
    ocr_res = process_document_ocr(file_bytes, filename)
    extracted_text = ocr_res.get("extracted_text", "")
    ocr_status = ocr_res.get("ocr_status", "SUCCESS")
    file_type = ocr_res.get("file_type", "Document")

    # 2. Text Scam Analysis (Message ML model + rule engine)
    text_analysis = analyze_document_extracted_text(ocr_res)
    text_risk_score = float(text_analysis.get("risk_score", 0.0))

    # 3. URL Extraction & Hybrid Link Analysis
    url_extraction_res = extract_urls_from_text(extracted_text)
    raw_url_items = url_extraction_res.get("urls", [])
    url_analysis = analyze_extracted_url_list(raw_url_items)
    url_risk_score = float(url_analysis.get("highest_url_risk_score", 0.0))

    # 4. QR Code Scanner Integration
    qr_analysis = scan_qr_codes(file_bytes, filename)
    qr_risk_score = float(qr_analysis.get("highest_qr_risk_score", 0.0))

    # 5. Multi-Engine Risk Score Orchestration
    # Weighted base score
    weighted_score = (text_risk_score * 0.45) + (url_risk_score * 0.35) + (qr_risk_score * 0.20)
    
    # Preserve maximum individual threat score so high-risk single vector isn't diluted
    overall_score_val = max(weighted_score, text_risk_score, url_risk_score, qr_risk_score)
    final_risk_score = min(int(round(overall_score_val)), 100)

    # Determine Verdict cleanly without assigning misleading SAFE to unscannable files
    if final_risk_score >= 70:
        final_risk_level = "HIGH RISK"
    elif final_risk_score >= 40:
        final_risk_level = "SUSPICIOUS"
    else:
        has_text_content = ocr_status in ("SUCCESS", "OCR_FALLBACK") and bool(extracted_text and extracted_text.strip())
        has_url_content = url_analysis.get("url_count", 0) > 0
        has_qr_content = qr_analysis.get("qr_found", False)

        if has_text_content or has_url_content or has_qr_content:
            final_risk_level = "SAFE"
        else:
            final_risk_level = "UNSCANNABLE"

    # 6. Synthesize Indicators & Reasons
    combined_indicators: List[str] = []
    combined_reasons: List[str] = []

    # Text indicators
    text_inds = text_analysis.get("indicators") or text_analysis.get("detected_indicators") or []
    for ind in text_inds:
        if ind not in combined_indicators:
            combined_indicators.append(ind)

    # URL indicators & reasons
    url_items = url_analysis.get("urls", [])
    for analyzed_url in url_items:
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

    # Text reasons
    for rsn in text_analysis.get("reasons", []):
        if rsn not in combined_reasons:
            combined_reasons.append(rsn)
    for rsn in qr_analysis.get("reasons", []):
        if rsn not in combined_reasons:
            combined_reasons.append(rsn)

    # If unscannable, ensure reason explains the status
    if final_risk_level == "UNSCANNABLE":
        ocr_err = ocr_res.get("error")
        unscannable_reason = ocr_err or f"File content could not be reliably analyzed (OCR Status: {ocr_status})."
        if unscannable_reason not in combined_reasons:
            combined_reasons.insert(0, unscannable_reason)

    # 7. Formulate Contextual Guidance & Summary
    if final_risk_level == "HIGH RISK":
        recommended_action = (
            "CRITICAL: Do not interact with links, QR codes, or instructions in this document. "
            "It exhibits strong fraudulent scam patterns or dangerous malware links."
        )
    elif final_risk_level == "SUSPICIOUS":
        recommended_action = (
            "WARNING: Exercise caution. This document contains suspicious language, unverified links, "
            "or payment requests. Verify the sender through official channels before acting."
        )
    elif final_risk_level == "UNSCANNABLE":
        recommended_action = (
            "This file could not be fully analyzed. Do not trust it without verifying the source."
        )
    else:
        recommended_action = (
            "No significant scam or phishing threats detected. Ensure document origin is trusted."
        )

    if final_risk_level == "UNSCANNABLE":
        summary_msg = f"Document could not be reliably analyzed (Status: {ocr_status}). Risk Level: UNSCANNABLE."
    else:
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
            "verdict": text_analysis.get("verdict") or text_analysis.get("text_verdict", "SAFE"),
            "ml_prediction": text_analysis.get("ml_prediction"),
            "scam_probability": text_analysis.get("scam_probability"),
            "detected_indicators": text_inds
        },
        "url_analysis": {
            "url_count": url_analysis.get("url_count", 0),
            "highest_risk_score": url_risk_score,
            "verdict": url_analysis.get("overall_url_verdict", "SAFE"),
            "analyzed_urls": url_analysis.get("urls", [])
        },
        "qr_analysis": {
            "qr_found": qr_analysis.get("qr_found", False),
            "qr_count": qr_analysis.get("qr_count", 0),
            "highest_risk_score": qr_risk_score,
            "verdict": qr_analysis.get("qr_verdict", "SAFE"),
            "qr_codes": qr_analysis.get("qr_codes", [])
        },
        "threat_breakdown": {
            "text_risk_score": text_risk_score,
            "url_risk_score": url_risk_score,
            "qr_risk_score": qr_risk_score,
            "final_score": final_risk_score
        }
    }
