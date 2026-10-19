"""
=============================================================================
KAVACH — Document URL Security Analyzer
=============================================================================
Integrates with the existing Hybrid URL Security Engine (analyze_link_url)
to analyze all URLs extracted from document text or QR codes.

Key Features:
  - Reuses existing hybrid URL scanner & Random Forest ML model
  - Evaluates static heuristic indicators & ML phishing probabilities
  - Aggregates overall URL risk score, verdict, and threat count
  - Zero outbound HTTP network requests (SSRF safe)
  - Safe error handling for malformed URLs
=============================================================================
"""

import logging
from typing import Any, Dict, List, Optional

from app.services.link_scanner import analyze_link_url
from app.services.document_url_extractor import extract_urls_from_text

logger = logging.getLogger("kavach.services.document_url_analyzer")


def analyze_extracted_url_list(url_items: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Analyzes a list of extracted URL dictionaries using the existing Hybrid URL Scanner.

    Inputs:
      url_items: List of dicts [{'url': 'https://...', 'raw_extracted': '...', 'source': 'document_text'}]

    Returns:
      Dict with list of analyzed URL results, highest_url_risk_score,
      overall_url_verdict, flagged_urls_count, url_count, success.
    """
    if not url_items:
        return {
            "success": True,
            "urls": [],
            "url_count": 0,
            "highest_url_risk_score": 0,
            "overall_url_verdict": "SAFE",
            "flagged_urls_count": 0,
            "message": "No URLs found in the document",
            "error": None,
        }

    analyzed_results: List[Dict[str, Any]] = []
    highest_score = 0
    flagged_count = 0

    for item in url_items:
        target_url = item.get("url", "").strip()
        raw_extracted = item.get("raw_extracted", target_url)
        source = item.get("source", "document_text")

        if not target_url:
            continue

        try:
            # Reuses existing Hybrid URL Scanner (analyze_link_url)
            scan_res = analyze_link_url(target_url)

            verdict = scan_res.get("verdict", "SAFE")
            risk_score = scan_res.get("risk_score", 0)

            if risk_score > highest_score:
                highest_score = risk_score

            if risk_score >= 30 or verdict in ("SUSPICIOUS", "HIGH RISK"):
                flagged_count += 1

            url_entry = {
                "url": target_url,
                "raw_extracted": raw_extracted,
                "source": source,
                "verdict": verdict,
                "risk_level": scan_res.get("risk_level", "LOW"),
                "risk_score": risk_score,
                "heuristic_score": scan_res.get("heuristic_score", risk_score),
                "ml_verdict": scan_res.get("ml_verdict"),
                "ml_confidence": scan_res.get("ml_confidence"),
                "ml_phishing_probability": scan_res.get("ml_phishing_probability"),
                "ml_safe_probability": scan_res.get("ml_safe_probability"),
                "model": scan_res.get("model", "Random Forest Classifier"),
                "model_scope": scan_res.get("model_scope", "ISCX Phishing Benchmark"),
                "indicators": scan_res.get("indicators", []),
                "reasons": scan_res.get("reasons", []),
                "recommendation": scan_res.get("recommendation", ""),
                "error": None,
            }
            analyzed_results.append(url_entry)
        except Exception as err:
            logger.error(f"Error analyzing extracted URL '{target_url}': {err}", exc_info=True)
            analyzed_results.append({
                "url": target_url,
                "raw_extracted": raw_extracted,
                "source": source,
                "verdict": "UNKNOWN",
                "risk_level": "UNKNOWN",
                "risk_score": 0,
                "heuristic_score": 0,
                "ml_verdict": None,
                "ml_confidence": None,
                "ml_phishing_probability": None,
                "ml_safe_probability": None,
                "model": None,
                "model_scope": None,
                "indicators": [],
                "reasons": [f"Analysis error for URL: {str(err)}"],
                "recommendation": "Exercise caution. URL could not be scanned safely.",
                "error": str(err),
            })

    # Determine overall document URL verdict
    if highest_score >= 60 or any(u["verdict"] == "HIGH RISK" for u in analyzed_results):
        overall_url_verdict = "HIGH_RISK"
    elif highest_score >= 30 or any(u["verdict"] == "SUSPICIOUS" for u in analyzed_results):
        overall_url_verdict = "SUSPICIOUS"
    else:
        overall_url_verdict = "SAFE"

    message = f"Analyzed {len(analyzed_results)} URLs from document. Highest risk score: {highest_score}/100."

    logger.info(f"Document URL Analysis: {len(analyzed_results)} URLs analyzed, overall_verdict={overall_url_verdict}, highest_score={highest_score}")

    return {
        "success": True,
        "urls": analyzed_results,
        "url_count": len(analyzed_results),
        "highest_url_risk_score": highest_score,
        "overall_url_verdict": overall_url_verdict,
        "flagged_urls_count": flagged_count,
        "message": message,
        "error": None,
    }


def extract_and_analyze_document_urls(text: str, source_label: str = "document_text") -> Dict[str, Any]:
    """
    Combined helper function to extract URLs from text and immediately run Hybrid URL Security analysis.
    """
    extractor_res = extract_urls_from_text(text, source_label=source_label)
    if not extractor_res["success"] or not extractor_res["urls"]:
        return {
            "success": True,
            "urls": [],
            "url_count": 0,
            "highest_url_risk_score": 0,
            "overall_url_verdict": "SAFE",
            "flagged_urls_count": 0,
            "message": "No URLs found in the document",
            "error": None,
        }

    return analyze_extracted_url_list(extractor_res["urls"])
