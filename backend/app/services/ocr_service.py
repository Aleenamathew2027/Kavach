"""
=============================================================================
KAVACH — Safe OCR & Text Extraction Service
=============================================================================
Safely extracts textual content from PDFs, Word documents, text files,
and image formats (PNG, JPG, JPEG, BMP, WEBP).

Security & Stability Features:
  - Enforces strict 10 MB maximum file size limit
  - No external network calls
  - No file execution (reads binary streams in memory)
  - Native text extraction for selectable PDFs, DOCX, and TXT
  - Fallback OCR for scanned PDFs and images via Pillow & PyTesseract
  - Graceful handling when Tesseract OCR binary is not installed
  - Privacy-focused: Does not persist sensitive text to disk
=============================================================================
"""

import io
import os
import re
import shutil
import logging
from typing import Any, Dict, Optional, Tuple

import pypdf
import docx
from PIL import Image

try:
    import pytesseract
except ImportError:
    pytesseract = None

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

logger = logging.getLogger("kavach.services.ocr_service")

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit
SUPPORTED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
SUPPORTED_DOC_EXTS = {".pdf", ".docx", ".doc", ".txt"}


def check_tesseract_availability() -> Tuple[bool, Optional[str]]:
    """
    Checks whether Tesseract OCR binary is available via environment variable TESSERACT_CMD,
    system PATH, or standard installation directories.
    """
    if pytesseract is None:
        return False, None

    # 1. Environment variable override
    env_tess_cmd = os.getenv("TESSERACT_CMD")
    if env_tess_cmd and os.path.exists(env_tess_cmd):
        pytesseract.pytesseract.tesseract_cmd = env_tess_cmd
        return True, env_tess_cmd

    # 2. Standard Windows and Unix installation paths
    candidate_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
        os.path.expandvars(r"%USERPROFILE%\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/opt/homebrew/bin/tesseract"
    ]

    for path in candidate_paths:
        if path and os.path.exists(path):
            pytesseract.pytesseract.tesseract_cmd = path
            return True, path

    # 3. System PATH lookup
    cmd_in_path = shutil.which("tesseract") or shutil.which("tesseract.exe")
    if cmd_in_path:
        pytesseract.pytesseract.tesseract_cmd = cmd_in_path
        return True, cmd_in_path

    return False, None


def extract_text_from_pdf(file_bytes: bytes) -> Tuple[str, int, bool]:
    """
    Extracts text from PDF bytes using PyMuPDF (fitz) or pypdf.
    Returns (extracted_text, page_count, has_selectable_text).
    """
    page_count = 0
    pages_text = []

    # Try PyMuPDF (fitz) first for fast, high-accuracy text extraction
    if fitz is not None:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            page_count = len(doc)
            for page in doc:
                txt = page.get_text()
                if txt and txt.strip():
                    pages_text.append(txt.strip())
            full_text = "\n\n".join(pages_text)
            if full_text.strip():
                return full_text, page_count, True
        except Exception as e:
            logger.warning(f"PyMuPDF PDF extraction failed: {e}. Falling back to pypdf.")

    # Fallback to pypdf
    try:
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        page_count = len(reader.pages)
        for page in reader.pages[:50]:  # Limit to 50 pages safely
            txt = page.extract_text()
            if txt and txt.strip():
                pages_text.append(txt.strip())
        full_text = "\n\n".join(pages_text)
        has_text = bool(full_text.strip())
        return full_text, page_count, has_text
    except Exception as e:
        logger.error(f"pypdf PDF extraction failed: {e}")
        return "", page_count, False


def ocr_pdf_pages(file_bytes: bytes) -> Tuple[str, Optional[float]]:
    """
    Performs fallback OCR on PDF page images when no selectable text exists.
    Requires PyMuPDF (fitz) and Tesseract binary.
    """
    if fitz is None or pytesseract is None:
        return "", None

    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        ocr_texts = []
        confidences = []

        for page in doc[:10]:  # OCR up to first 10 pages max
            pix = page.get_pixmap(dpi=150)
            img_bytes = pix.tobytes("png")
            img = Image.open(io.BytesIO(img_bytes))

            # Run pytesseract OCR
            txt = pytesseract.image_to_string(img)
            if txt and txt.strip():
                ocr_texts.append(txt.strip())

            # Attempt confidence check
            try:
                data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DATAFRAME)
                valid_confs = data[data.conf > 0]["conf"]
                if not valid_confs.empty:
                    confidences.append(float(valid_confs.mean()))
            except Exception:
                pass

        full_ocr_text = "\n\n".join(ocr_texts)
        avg_conf = float(sum(confidences) / len(confidences)) if confidences else None
        return full_ocr_text, avg_conf
    except Exception as err:
        logger.error(f"PDF page OCR failed: {err}")
        return "", None


def extract_text_from_docx(file_bytes: bytes) -> Tuple[str, bool]:
    """Extracts text from Word DOCX document bytes."""
    try:
        doc = docx.Document(io.BytesIO(file_bytes))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text.strip():
                        paragraphs.append(cell.text.strip())
        full_text = "\n".join(paragraphs)
        return full_text, bool(full_text.strip())
    except Exception as e:
        logger.error(f"DOCX extraction error: {e}")
        return "", False


def extract_text_from_image(file_bytes: bytes) -> Tuple[str, Optional[float], bool]:
    """
    Runs Tesseract OCR on raw image bytes (PNG, JPG, JPEG, BMP, WEBP).
    Returns (extracted_text, average_confidence, success).
    """
    if pytesseract is None:
        return "", None, False

    try:
        img = Image.open(io.BytesIO(file_bytes))
        # Convert paletted or RGBA to RGB for Tesseract compatibility
        if img.mode in ("RGBA", "LA", "P"):
            img = img.convert("RGB")

        extracted_text = pytesseract.image_to_string(img)

        # Attempt to get real OCR confidence from Tesseract data
        avg_conf = None
        try:
            data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DATAFRAME)
            valid_confs = data[data.conf > 0]["conf"]
            if not valid_confs.empty:
                avg_conf = round(float(valid_confs.mean()), 1)
        except Exception:
            avg_conf = None

        clean_text = extracted_text.strip() if extracted_text else ""
        return clean_text, avg_conf, True
    except Exception as e:
        logger.error(f"Image OCR processing failed: {e}")
        return "", None, False


def process_document_ocr(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Unified entry point for document and image text extraction / OCR.

    Enforces:
      - 10 MB maximum file size limit
      - File format validation
      - Safe in-memory text parsing
      - Graceful Tesseract fallback & status tracking
    """
    if not filename or not filename.strip():
        filename = "uploaded_file"

    ext = os.path.splitext(filename)[1].lower()

    # 1. Validate File Size (10 MB limit)
    if not file_bytes or len(file_bytes) == 0:
        return {
            "success": False,
            "extracted_text": "",
            "ocr_status": "FAILED",
            "ocr_confidence": None,
            "character_count": 0,
            "word_count": 0,
            "page_count": 0,
            "error": "Empty or corrupted file uploaded.",
        }

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        return {
            "success": False,
            "extracted_text": "",
            "ocr_status": "FILE_TOO_LARGE",
            "ocr_confidence": None,
            "character_count": 0,
            "word_count": 0,
            "page_count": 0,
            "error": "File size exceeds maximum allowable limit of 10 MB.",
        }

    # 2. Check Tesseract OCR Engine Status
    tess_available, tess_path = check_tesseract_availability()

    # 3. Process PDF Documents
    if ext == ".pdf":
        text, page_count, has_selectable = extract_text_from_pdf(file_bytes)

        if has_selectable and text.strip():
            words = len(text.split())
            chars = len(text)
            return {
                "success": True,
                "extracted_text": text.strip(),
                "ocr_status": "SUCCESS",
                "ocr_confidence": None,  # Native text extraction has no OCR confidence
                "character_count": chars,
                "word_count": words,
                "page_count": page_count,
                "error": None,
            }

        # PDF has no selectable text (scanned PDF image)
        if not tess_available:
            return {
                "success": False,
                "extracted_text": "",
                "ocr_status": "OCR_UNAVAILABLE",
                "ocr_confidence": None,
                "character_count": 0,
                "word_count": 0,
                "page_count": page_count,
                "error": "PDF contains scanned images without selectable text. Tesseract OCR binary is not installed on system PATH.",
            }

        # Run Fallback OCR on scanned PDF pages
        ocr_text, avg_conf = ocr_pdf_pages(file_bytes)
        if ocr_text and ocr_text.strip():
            clean_txt = ocr_text.strip()
            return {
                "success": True,
                "extracted_text": clean_txt,
                "ocr_status": "OCR_FALLBACK",
                "ocr_confidence": avg_conf,
                "character_count": len(clean_txt),
                "word_count": len(clean_txt.split()),
                "page_count": page_count,
                "error": None,
            }
        else:
            return {
                "success": True,
                "extracted_text": "",
                "ocr_status": "NO_TEXT_FOUND",
                "ocr_confidence": None,
                "character_count": 0,
                "word_count": 0,
                "page_count": page_count,
                "error": "No readable text found in scanned PDF pages.",
            }

    # 4. Process Word Documents (.docx, .doc)
    elif ext in (".docx", ".doc"):
        text, has_text = extract_text_from_docx(file_bytes)
        if has_text:
            clean_txt = text.strip()
            return {
                "success": True,
                "extracted_text": clean_txt,
                "ocr_status": "SUCCESS",
                "ocr_confidence": None,
                "character_count": len(clean_txt),
                "word_count": len(clean_txt.split()),
                "page_count": 1,
                "error": None,
            }
        else:
            return {
                "success": True,
                "extracted_text": "",
                "ocr_status": "NO_TEXT_FOUND",
                "ocr_confidence": None,
                "character_count": 0,
                "word_count": 0,
                "page_count": 1,
                "error": "No text content found in Word document.",
            }

    # 5. Process Plain Text Files (.txt)
    elif ext == ".txt":
        try:
            text = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = file_bytes.decode("latin-1", errors="ignore")
        clean_txt = text.strip()
        has_text = bool(clean_txt)
        return {
            "success": True,
            "extracted_text": clean_txt,
            "ocr_status": "SUCCESS" if has_text else "NO_TEXT_FOUND",
            "ocr_confidence": None,
            "character_count": len(clean_txt),
            "word_count": len(clean_txt.split()),
            "page_count": 1,
            "error": None if has_text else "Empty text file.",
        }

    # 6. Process Image Files (.png, .jpg, .jpeg, .bmp, .webp)
    elif ext in SUPPORTED_IMAGE_EXTS:
        if not tess_available:
            return {
                "success": False,
                "extracted_text": "",
                "ocr_status": "OCR_UNAVAILABLE",
                "ocr_confidence": None,
                "character_count": 0,
                "word_count": 0,
                "page_count": 1,
                "error": "Image document received, but Tesseract OCR binary is not installed on system PATH.",
            }

        text, avg_conf, ok = extract_text_from_image(file_bytes)
        if not ok:
            return {
                "success": False,
                "extracted_text": "",
                "ocr_status": "FAILED",
                "ocr_confidence": None,
                "character_count": 0,
                "word_count": 0,
                "page_count": 1,
                "error": "Failed to open or decode image file.",
            }

        if text and text.strip():
            clean_txt = text.strip()
            return {
                "success": True,
                "extracted_text": clean_txt,
                "ocr_status": "SUCCESS",
                "ocr_confidence": avg_conf,
                "character_count": len(clean_txt),
                "word_count": len(clean_txt.split()),
                "page_count": 1,
                "error": None,
            }
        else:
            return {
                "success": True,
                "extracted_text": "",
                "ocr_status": "NO_TEXT_FOUND",
                "ocr_confidence": None,
                "character_count": 0,
                "word_count": 0,
                "page_count": 1,
                "error": "No readable text detected in image via OCR.",
            }

    # 7. Unsupported File Format
    else:
        return {
            "success": False,
            "extracted_text": "",
            "ocr_status": "UNSUPPORTED_FILE",
            "ocr_confidence": None,
            "character_count": 0,
            "word_count": 0,
            "page_count": 0,
            "error": f"Unsupported file extension '{ext}'. Supported formats: PDF, DOCX, TXT, PNG, JPG, JPEG, BMP, WEBP.",
        }
