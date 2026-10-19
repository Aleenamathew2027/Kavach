"""
=============================================================================
KAVACH — Safe Document URL Extractor
=============================================================================
Extracts, cleans, normalizes, and deduplicates URLs from document text
without making outbound HTTP requests (SSRF-safe).

Supports:
  - http:// and https:// links
  - www. domain prefixes
  - Trimming surrounding punctuation (parentheses, brackets, quotes, trailing dots)
  - Deduplication preserving discovery order
=============================================================================
"""

import re
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("kavach.services.document_url_extractor")

# Regex to detect HTTP, HTTPS, and www. URLs
URL_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)

# Trailing punctuation to strip from extracted URLs
TRAILING_PUNCTUATION = '.,;:!?"\')}]>'
LEADING_PUNCTUATION = '("\'[{<'


def clean_extracted_url(raw_url: str) -> Optional[str]:
    """
    Cleans raw extracted URL candidate by stripping leading/trailing punctuation
    and validating URL structure.
    """
    if not raw_url:
        return None

    clean = raw_url.strip()

    # Strip leading/trailing punctuation
    clean = clean.lstrip(LEADING_PUNCTUATION).rstrip(TRAILING_PUNCTUATION)

    # Balance trailing parentheses if missing matching opening parenthesis
    if clean.endswith(")") and clean.count("(") < clean.count(")"):
        clean = clean[:-1].rstrip(TRAILING_PUNCTUATION)

    if not clean or len(clean) < 4:
        return None

    # Prepend scheme for www. links for clean parsing
    normalized = clean
    if clean.lower().startswith("www."):
        normalized = "https://" + clean

    try:
        parsed = urlparse(normalized)
        if parsed.hostname and len(parsed.hostname) >= 3:
            return clean
    except Exception:
        pass

    return None


def extract_urls_from_text(text: str, source_label: str = "document_text") -> Dict[str, Any]:
    """
    Extracts, cleans, and deduplicates all URLs found in the given text.

    Inputs:
      text: Extracted OCR / PDF / DOCX document text
      source_label: Label indicating origin (e.g. 'document_text', 'qr_code')

    Returns:
      Dict containing:
        - success (bool)
        - urls (list of dicts with 'url', 'raw_extracted', 'source')
        - url_count (int)
        - error (Optional[str])
    """
    if not text or not text.strip():
        return {
            "success": True,
            "urls": [],
            "url_count": 0,
            "error": None,
        }

    matches = URL_PATTERN.findall(text)
    extracted_items: List[Dict[str, str]] = []
    seen_urls = set()

    for match in matches:
        cleaned = clean_extracted_url(match)
        if cleaned:
            # Normalize for deduplication check
            norm_key = cleaned.lower()
            if norm_key.startswith("www."):
                norm_key = "https://" + norm_key
            if not norm_key.startswith("http://") and not norm_key.startswith("https://"):
                norm_key = "https://" + norm_key

            if norm_key not in seen_urls:
                seen_urls.add(norm_key)

                # Format normalized URL for analysis
                analysis_url = cleaned
                if cleaned.lower().startswith("www."):
                    analysis_url = "https://" + cleaned

                extracted_items.append({
                    "url": analysis_url,
                    "raw_extracted": cleaned,
                    "source": source_label,
                })

    logger.info(f"Extracted {len(extracted_items)} unique URLs from {source_label}.")

    return {
        "success": True,
        "urls": extracted_items,
        "url_count": len(extracted_items),
        "error": None,
    }
