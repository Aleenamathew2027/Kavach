# KAVACH
## An Agentic AI Guardian Against AI-Powered Scams

---

## 1. Project Overview
**KAVACH** is a multi-channel cybersecurity defense system designed to protect users against modern AI-driven scam messages, deceptive phishing URLs, corrupted document attachments, and malicious QR codes. It pairs real-time machine learning threat detection with a privacy-preserving family guardian alert network and an administrator Security Operations Center (SOC) dashboard.

---

## 2. Problem Statement
Cybercriminals leverage automated tools to generate convincing phishing messages, obscure malicious links within shortened URLs, embed malware in documents, and craft malicious QR code payment requests. Non-technical users—especially elderly family members—often struggle to evaluate these digital threats. Existing security tools operate in silos and fail to notify trusted guardians without violating user data privacy.

---

## 3. Objectives
1. **Multi-Vector Threat Detection**: Analyze messages, URLs, documents, and QR codes through dedicated ML models and heuristic scanners.
2. **Guardian Alert Feed**: Provide trusted family guardians with real-time threat notifications without exposing private messages or sensitive text.
3. **Admin Security Operations**: Offer administrators aggregate security metrics, user monitoring, and threat trends.
4. **Production Hardening**: Ensure strict role-based access control (RBAC), multi-tenant user data isolation, and safe fallback handling for unscannable documents.

---

## 4. Main Features
* **AI Message Scam Detector**: Classifies suspicious text messages using a trained Logistic Regression model and heuristic rule engine.
* **Hybrid Link Scanner**: Analyzes suspicious URLs offline using a trained Random Forest model and lexical/structural feature extraction.
* **Document & Image Scanner**: Safely extracts text from PDF, DOCX, and TXT files, parses embedded links, and assigns multi-engine risk verdicts.
* **In-Memory QR Code Analyzer**: Decodes QR code payloads using OpenCV and flags suspicious payment or phishing payloads.
* **Unscannable Document Protection**: Guarantees that empty, corrupted, or unextractable files receive an `UNSCANNABLE` verdict and are **never** marked as `SAFE`.
* **Privacy-Preserving Guardian Access**: Allows users to authorize trusted guardians using a 6-digit access code. Guardians view safety statuses without seeing confidential text.
* **Admin SOC Dashboard**: Centralized dashboard for system-wide user management, threat analytics, and activity logging.

---

## 5. System Architecture

```text
               User / Browser
                     │
             React + Vite Frontend
                     │
             FastAPI REST Backend
                     │
           Role-Based Access Control
       (User, Admin, Guardian Roles)
                     │
  ┌──────────────────┼──────────────────┬──────────────────┐
  │                  │                  │                  │
Message ML        URL Hybrid        Document Text       QR Code
 Detector          Detector          Extractor          Scanner
(Logistic Reg.)  (Random Forest)   (PDF/DOCX/TXT)      (OpenCV)
  │                  │                  │                  │
  └──────────────────┴─────────┬────────┴──────────────────┘
                               │
                    Risk Orchestrator
                               │
                      PostgreSQL Database
                               │
            ┌──────────────────┴──────────────────┐
      User Dashboard                       Guardian Feed
  (Personal Security Scans)             (Privacy-Safe Alerts)
```

---

## 6. AI/ML Components
1. **Message Scam Model**:
   - **Algorithm**: Logistic Regression classifier trained on SMS Spam benchmark data.
   - **Feature Extraction**: TF-IDF Vectorizer (`TfidfVectorizer`).
   - **Output**: Scam probability score, classification (`SAFE`, `SUSPICIOUS`, `SCAM`), and explanation.
2. **URL Phishing Model**:
   - **Algorithm**: Random Forest classifier trained on ISCX Phishing benchmark data.
   - **Feature Extraction**: Offline lexical feature extractor (URL length, subdomain count, IP usage, `@` symbol detection, digit count).
   - **Output**: Phishing probability, risk verdict, and indicator breakdown.
3. **QR Code Analyzer**:
   - **Library**: OpenCV `QRCodeDetector`.
   - **Output**: Payload string decoding, UPI payment URI classification, and URL risk analysis.

---

## 7. Technology Stack
* **Frontend**: React 18, Vite, Vanilla CSS.
* **Backend**: Python 3.11, FastAPI, Uvicorn, Pydantic.
* **Machine Learning & CV**: scikit-learn, joblib, OpenCV, NumPy, Pillow.
* **Text Processing**: PyMuPDF (`fitz`), `pypdf`, `python-docx`.
* **Database & ORM**: PostgreSQL, SQLAlchemy, Alembic.
* **Authentication**: JWT (JSON Web Tokens), Bcrypt password hashing (`pwdlib`).

---

## 8. Security Features
* **Role-Based Access Control (RBAC)**: Endpoint-level role isolation (`user`, `admin`, `guardian`).
* **Multi-Tenant User Isolation**: Queries filter strictly on authenticated `user_id`. User A cannot read or modify User B's alerts.
* **Zero Outbound HTTP Scanning**: Link scanner runs entirely offline without making external HTTP/SSRF network calls.
* **In-Memory Byte Processing**: Uploaded documents are parsed directly from byte buffers in memory without writing executable files to disk.
* **Environment Hardening**: Production mode requires strong JWT secret keys; CORS origins are strictly configurable.

---

## 9. User, Admin, and Guardian Roles
* **User**: Can run message, link, document, and QR scans; view personal alerts; generate/revoke 6-digit guardian access codes.
* **Guardian**: Authenticates via 6-digit code to view protected family member safety status and sanitized threat notifications.
* **Admin**: Accesses SOC dashboard, system-wide threat analytics, user list, and chronological audit logs.

---

## 10. Installation

### Prerequisites
* Python 3.10+
* Node.js v18+ & npm
* PostgreSQL 14+ running on port 5432

### Backend Setup
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

### Frontend Setup
```bash
cd frontend
npm install
```

---

## 11. Running Locally

1. **Start PostgreSQL Database**: Ensure database `kavach_db` is running on port 5432.
2. **Start Backend API**:
   ```bash
   cd backend
   .\venv\Scripts\activate
   uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```
   API Docs: `http://127.0.0.1:8000/docs`  
   Health Check: `http://127.0.0.1:8000/health`
3. **Start Frontend Client**:
   ```bash
   cd frontend
   npm run dev
   ```
   App URL: `http://127.0.0.1:5173`

---

## 12. Testing

Run full backend test suite (116 unit & integration tests):
```bash
cd backend
.\venv\Scripts\python.exe -m pytest -v
```

Run frontend production build verification:
```bash
cd frontend
npm run build
```

---

## 13. Demonstration Flow
1. **User Registration & Login**: Register a new user account and log in.
2. **Message Scanner**: Test safe message vs scam message (`URGENT! Bank account suspended`).
3. **Link Scanner**: Test safe URL vs suspicious phishing link.
4. **Document Scanner**: Upload text file; upload corrupted/empty file to verify `UNSCANNABLE` protection.
5. **QR Scanner**: Test image containing QR code payload.
6. **Guardian Pairing**: Generate 6-digit code, log out, authenticate as Guardian, and view privacy-preserved alerts.
7. **Admin Dashboard**: Log in as Admin (`admin@kavach.com`) to view SOC metrics and audit logs.

---

## 14. Limitations
* **Tesseract Binary Requirement**: Optical Character Recognition on PNG/JPG images requires installing Tesseract binary on the host OS (`C:\Program Files\Tesseract-OCR`). Without it, image scans return `UNSCANNABLE`.
* **No Deepfake or Forgery Analysis**: KAVACH analyzes text, links, and QR codes; it does not perform audio/video deepfake verification or forensic document forgery analysis.
* **Offline URL Scanner**: Phishing detection relies on lexical heuristics and trained ML models without live web page scraping.

---

## 15. Future Enhancements
* Real-time audio deepfake voice call detection.
* Docker containerization deployment scripts (`docker-compose.yml`).
* Automated cloud deployment on AWS/GCP with Kubernetes.
* Real-time WebSocket push notifications for guardians.
