# KAVACH — Project Limitations & Technical Scope Boundaries

This document outlines the current technical boundaries, host environment constraints, and explicit scope limits of the KAVACH system.

---

## 1. Environment & Dependency Limitations

### Host Tesseract OCR Binary Status
* **Status**: **Not Installed on Host System PATH**
* **Impact**: Optical Character Recognition on PNG, JPG, and BMP image files requires the Tesseract OCR engine binary (`tesseract.exe`) installed on the host operating system (`C:\Program Files\Tesseract-OCR\tesseract.exe`).
* **System Behavior**: When images or scanned PDFs are uploaded on host machines without Tesseract installed, `ocr_service.py` catches `PyTesseractNotFoundError` / `FileNotFoundError` and safely assigns `ocr_status="OCR_UNAVAILABLE"` and `risk_level="UNSCANNABLE"`.
* **Native Text Extraction**: Native PDF text extraction (via `pypdf` / `PyMuPDF`), Word document extraction (`python-docx`), and plain text parsing (`.txt`) operate independently and remain 100% functional.

### Docker Runtime Testing Status
* **Status**: **Files Created, Container Runtime Unverified**
* **Impact**: Standard production Docker configuration files (`docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx.conf`, `.dockerignore`) have been created. However, Docker Desktop engine is not installed on this development machine (`docker: CommandNotFoundException`).
* **System Behavior**: Container startup commands (`docker-compose up`) could not be executed locally. The project runs directly via Python virtual environment (`uvicorn`) and Node.js (`vite`).

---

## 2. Functional Scope & Feature Limits

### No Deepfake Voice or Video Detection
* **Scope Boundary**: KAVACH analyzes text communications, embedded URL links, document attachments, and QR code payloads.
* **Non-Claim**: The system does **NOT** perform audio deepfake voice call detection, video facial forgery analysis, or speech synthesis identification.

### No Forensic Document Forgery Detection
* **Scope Boundary**: The document scanner extracts text content and inspects embedded links and QR codes for fraud indicators.
* **Non-Claim**: The system does **NOT** perform forensic document forgery analysis, digital signature validation, handwriting verification, or image manipulation detection (EXIF/metadata tampering).

### URL Phishing Detection Boundaries
* **Scope Boundary**: The URL scanner uses offline lexical feature extraction (subdomain counts, IP address usage, character ratios) and a Random Forest ML model trained on benchmark data.
* **Non-Claim**: The scanner operates entirely offline without making live HTTP connection requests to target web pages (SSRF safety). It cannot guarantee 100% detection of zero-day phishing domains that rely solely on dynamic JavaScript redirects or cloaked landing pages.

### Machine Learning Dataset & Domain Boundaries
* **Scope Boundary**: The message scam model is trained on standard SMS Spam & Phishing benchmark datasets using Logistic Regression and TF-IDF vectorization.
* **Non-Claim**: Model predictions represent statistical scam probabilities based on trained patterns. They do not constitute absolute legal or financial guarantees of safety.

### QR Code Payload Decoding Dependency
* **Scope Boundary**: QR code scanning relies on OpenCV `QRCodeDetector` locating and decoding binary QR patterns within uploaded images.
* **Non-Claim**: Severely degraded, heavily blurred, or low-resolution images where the QR finder patterns cannot be mathematically isolated will not yield a payload and are marked `UNSCANNABLE`.

---

## 3. Deployment & Infrastructure Boundaries

### Production HTTPS & Domain Certificates
* **Scope Boundary**: Local development runs on HTTP (`http://127.0.0.1:8000` for backend, `http://127.0.0.1:5173` for frontend).
* **Non-Claim**: HTTPS / TLS certificate termination (e.g. Let's Encrypt / Certbot) must be configured on the host Nginx reverse proxy during final cloud deployment.
