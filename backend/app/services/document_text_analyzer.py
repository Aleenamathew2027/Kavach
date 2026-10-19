"""
=============================================================================
KAVACH — Document OCR Text Scam Analyzer
=============================================================================
Analyzes text extracted from documents and images using the existing trained
Message Scam ML model (Logistic Regression trained on SMS Spam benchmark)
and rule-based explainable threat indicators.

Key Features:
  - Reuses trained message scam model (`predict_message_scam`)
  - Evaluates urgency, financial demands, credential harvesting, impersonation
  - Handles OCR status codes (NO_TEXT_FOUND, OCR_UNAVAILABLE, FAILED, etc.)
  - Returns structured verdicts: SAFE, SUSPICIOUS, HIGH_RISK, or UNKNOWN
  - Strict privacy protection (never logs full private document text)
=============================================================================
"""

import logging
from typing import Any, Dict, List, Optional

from app.ai.message_detector import predict_message_scam
from app.services.message_scanner import analyze_message_text

logger = logging.getLogger("kavach.services.document_text_analyzer")


def analyze_document_extracted_text(ocr_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes OCR/extracted document text for scam and fraudulent indicators.

    Inputs:
      ocr_result: Output dictionary from process_document_ocr()

    Returns:
      Dict with verdict (SAFE, SUSPICIOUS, HIGH_RISK, UNKNOWN), risk_score (0-100),
      confidence, scam_probability, model, indicators, reasons, character count.
    """
    ocr_status = ocr_result.get("ocr_status", "UNKNOWN")
    extracted_text = ocr_result.get("extracted_text", "")
    ocr_error = ocr_result.get("error")

    # Handle cases where no extractable text is available
    if ocr_status in ("NO_TEXT_FOUND", "OCR_UNAVAILABLE", "UNSUPPORTED_FILE", "FAILED", "FILE_TOO_LARGE") or not extracted_text or not extracted_text.strip():
        error_msg = ocr_error or f"No extractable text available for analysis (OCR Status: {ocr_status})."
        logger.info(f"Document text analysis skipped: {error_msg}")
        return {
            "success": False,
            "verdict": "UNKNOWN",
            "risk_score": 0,
            "confidence": 0.0,
            "scam_probability": 0.0,
            "model": "Fallback Heuristics",
            "indicators": [],
            "reasons": [error_msg],
            "analyzed_character_count": 0,
            "error": error_msg,
        }

    clean_text = extracted_text.strip()
    char_count = len(clean_text)

    # 1. Primary AI/ML Message Scam Prediction
    try:
        ml_res = predict_message_scam(clean_text)
        ml_pred = ml_res.get("prediction", "SAFE")
        scam_prob = float(ml_res.get("scam_probability", 0.0))
        safe_prob = float(ml_res.get("safe_probability", 1.0))
        ml_confidence = float(ml_res.get("confidence", 0.5))
        model_name = ml_res.get("model", "Logistic Regression Classifier")
    except Exception as ml_err:
        logger.error(f"Error calling Message Scam ML model: {ml_err}", exc_info=True)
        ml_pred = "SAFE"
        scam_prob = 0.0
        safe_prob = 1.0
        ml_confidence = 0.5
        model_name = "Rule Heuristics Fallback"

    # 2. Secondary Rule-Based Explainable Indicators Scanner
    rule_res = analyze_message_text(clean_text)
    rule_score = rule_res.get("risk_score", 0)
    rule_risk = rule_res.get("risk_level", "SAFE")
    detected_indicators = list(rule_res.get("detected_indicators", []))
    reasons = list(rule_res.get("reasons", []))

    # 3. Layered Combined Risk Score Calculation
    ml_score = int(round(scam_prob * 100.0))
    combined_score = int(round(ml_score * 0.60 + rule_score * 0.40))

    if scam_prob >= 0.70 or rule_risk == "HIGH RISK" or (ml_pred == "SCAM" and rule_risk == "SUSPICIOUS"):
        verdict = "HIGH_RISK"
        final_score = max(combined_score, 65)
    elif ml_pred == "SCAM" or rule_risk == "SUSPICIOUS" or combined_score >= 30:
        verdict = "SUSPICIOUS"
        final_score = max(combined_score, 35)
    else:
        verdict = "SAFE"
        final_score = combined_score

    final_score = max(0, min(100, final_score))

    # Prepend ML model explanation to reasons list
    scam_pct = round(scam_prob * 100.0, 1)
    ml_reason = f"AI Model ({model_name}): Evaluated document text as {ml_pred} with {ml_confidence * 100.0:.1f}% confidence ({scam_pct}% scam probability)."
    reasons.insert(0, ml_reason)

    logger.info(f"Analyzed document text ({char_count} chars): verdict={verdict}, score={final_score}, scam_prob={scam_pct}%")

    return {
        "success": True,
        "verdict": verdict,
        "risk_score": final_score,
        "confidence": round(ml_confidence * 100.0, 1),
        "scam_probability": scam_pct,
        "model": model_name,
        "indicators": detected_indicators,
        "reasons": reasons,
        "analyzed_character_count": char_count,
        "error": None,
    }
