"""
=============================================================================
KAVACH — Document & Image Security Scanner Service
=============================================================================
Delegates to the document risk orchestrator for multi-engine analysis:
  - OCR text extraction (PDF, DOCX, TXT, PNG, JPG, BMP, WEBP)
  - Trained Message ML Model scam detection
  - Hybrid URL ML & heuristic phishing detector
  - In-memory QR code payload & payment scanner
=============================================================================
"""

from typing import Any, Dict
from app.services.document_risk_orchestrator import orchestrate_document_risk

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit


def analyze_document_content(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Analyzes an uploaded document for fraudulent, deceptive, or scam patterns.
    Delegates to orchestrate_document_risk.
    """
    return orchestrate_document_risk(file_bytes, filename)
