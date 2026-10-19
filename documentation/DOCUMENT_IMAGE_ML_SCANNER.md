# KAVACH — ML-Based Document & Image Scam Detection Module

## 1. Overview
The **ML-Based Document & Image Scam Detection Module** enhances KAVACH's AI security pipeline to detect fraudulent documents, phishing images, fake payment invoices, malicious URL attachments, and dangerous embedded QR codes.

The system processes uploaded files (**PDF, DOCX, TXT, PNG, JPG, JPEG, BMP, WEBP**) through a 4-layer security pipeline and synthesizes a unified 0-100 risk verdict (**SAFE**, **SUSPICIOUS**, **HIGH_RISK**).

---

## 2. Multi-Engine Architecture

```
[ Uploaded File (PDF/DOCX/TXT/PNG/JPG/WEBP) ]
                       │
                       ▼
          [ Layer 1: Safe OCR & Text Extraction ]
     (Native PyMuPDF/pypdf/python-docx + Pillow/PyTesseract fallback)
                       │
                       ├─────────────────────────────────────┐
                       ▼                                     ▼
 [ Layer 2: Message ML & Rule Analyzer ]         [ Layer 3: URL Extractor ]
 (Reuses trained Logistic Regression ML model    (Regex HTTP/HTTPS/www extractor)
   + urgency, financial & OTP indicators)                    │
                       │                                     ▼
                       │                    [ Layer 3.5: Hybrid Link Scanner ]
                       │                    (Random Forest ML + 20+ static heuristics)
                       │                                     │
                       └──────────────────┬──────────────────┘
                                          │
                                          ▼
                      [ Layer 4: OpenCV In-Memory QR Scanner ]
                   (Decodes QR payloads: URLs, UPI handles, Crypto)
                                          │
                                          ▼
                     [ Multi-Engine Risk Score Orchestrator ]
         (Weighted Score + Max Threat Retention: 0-100 Risk Verdict)
                                          │
                                          ▼
                   [ DB Logging (SecurityScan / SecurityAlert) ]
                          & [ Frontend UI Visualization ]
```

---

## 3. Sub-Engine Specifications

### Layer 1: Safe OCR & Text Extraction (`ocr_service.py`)
- **Supported File Formats**: PDF, DOCX, TXT, PNG, JPG, JPEG, BMP, WEBP.
- **Security Limits**: Enforces strict 10 MB file size limit and in-memory parsing (zero temporary disk persistence).
- **Native PDF & DOCX Parsing**: Fast text extraction via `PyMuPDF` (`fitz`), `pypdf`, and `python-docx`.
- **Tesseract Fallback**: Uses `Pillow` and `PyTesseract` when image files or scanned image PDFs are provided. If Tesseract binary is not installed on system PATH, returns `OCR_UNAVAILABLE` status safely without crashing.

### Layer 2: OCR Text Scam Analysis (`document_text_analyzer.py`)
- **Trained Model Reuse**: Reuses `models/message_detector/message_model.joblib` (TF-IDF + Logistic Regression).
- **Explainable Indicators**: Evaluates urgency triggers, financial transfer demands, credential/OTP harvesting, and fake prize claims.
- **Privacy Protection**: Does not write private document text to logs or database records.

### Layer 3: Extracted Link Analysis (`document_url_extractor.py` & `document_url_analyzer.py`)
- **URL Extraction**: Safe regex extraction of HTTP, HTTPS, and www links.
- **Zero SSRF Risk**: Never makes outbound HTTP network connections to extracted link targets.
- **Hybrid Link Scanner Reuse**: Evaluates extracted URLs using `link_scanner.py` (Random Forest model trained on ISCX Phishing Benchmark + 20+ static heuristics).

### Layer 4: OpenCV QR Code Scanner (`qr_scanner.py`)
- **In-Memory Decoding**: Converts image bytes or PDF rendered page images (via PyMuPDF pixmaps) into OpenCV BGR arrays and scans for QR codes using `cv2.QRCodeDetector()`.
- **Payload Categorization**: Identifies URL payloads, UPI payment schemes (`upi://pay`), and Cryptocurrency wallet addresses.
- **Link & Payment Risk Integration**: Passes QR URLs to the hybrid link scanner and flags direct payment QR payloads with appropriate threat warnings.

### Layer 5: Document Risk Orchestrator (`document_risk_orchestrator.py`)
- **Risk Score Formula**:
  $$\text{Weighted Score} = (0.45 \times \text{Text Risk}) + (0.35 \times \text{URL Risk}) + (0.20 \times \text{QR Risk})$$
  $$\text{Final Score} = \min(100, \max(\text{Weighted Score}, \text{Text Risk}, \text{URL Risk}, \text{QR Risk}))$$
- **Verdict Thresholds**:
  - `HIGH RISK`: Score $\ge 70$
  - `SUSPICIOUS`: Score $40 - 69$
  - `SAFE`: Score $< 40$

---

## 4. Database & API Integration

- **Endpoint**: `POST /security/analyze-document`
- **Authentication**: JWT Bearer (`require_role(["user"])`).
- **Database Tracking**:
  - Automatically logs every scan to `SecurityScan` (scan_type="document").
  - On `HIGH RISK` detection, automatically creates a `SecurityAlert` (alert_type="document_scam") sanitized for Guardians (preserving text privacy).

---

## 5. Automated Test Verification Summary

| Test Module | Total Tests | Status |
| :--- | :---: | :---: |
| `test_ocr_service.py` | 9 | **PASSED** |
| `test_document_text_analyzer.py` | 9 | **PASSED** |
| `test_document_url_extractor.py` | 10 | **PASSED** |
| `test_document_url_analyzer.py` | 7 | **PASSED** |
| `test_qr_scanner.py` | 7 | **PASSED** |
| `test_document_risk_orchestrator.py` | 4 | **PASSED** |
| `test_document_api.py` | 3 | **PASSED** |
| `test_url_detector.py` | 14 | **PASSED** |
| `test_link_scanner.py` | 12 | **PASSED** |
| `test_auth_rbac.py` | 28 | **PASSED** |
| **TOTAL** | **103** | **100% PASSED** |
