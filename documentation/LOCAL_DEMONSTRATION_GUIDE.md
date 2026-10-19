# KAVACH — Local Demonstration Guide

Welcome to the **KAVACH Local Demonstration Guide**. This beginner-friendly document walks you step-by-step through running, testing, and demonstrating KAVACH on a local Windows machine.

---

## 1. Environment & Prerequisites

Before starting, ensure you have:
* Python 3.10+ (with virtual environment created in `backend/venv` or `.\venv`)
* Node.js v18+ and `npm`
* PostgreSQL 14+ running locally on port 5432 (or SQLite/local database configured)

---

## 2. Step-by-Step Local Execution Workflow

### Step 1: Start PostgreSQL Database
Ensure your local PostgreSQL service is running and database `kavach_db` exists:
```cmd
net start postgresql-x64-15
```

### Step 2: Activate Python Virtual Environment & Start Backend
Open Terminal 1 (PowerShell/CMD):
```cmd
cd c:\Users\This pc\Documents\Kavach_UML\kavach\backend
.\venv\Scripts\activate
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
* Backend interactive API docs will be accessible at: `http://127.0.0.1:8000/docs`
* System health status check: `http://127.0.0.1:8000/health`

### Step 3: Start React Frontend
Open Terminal 2 (PowerShell/CMD):
```cmd
cd c:\Users\This pc\Documents\Kavach_UML\kavach\frontend
npm run dev
```
* Open your browser and navigate to: `http://127.0.0.1:5173` (or `http://localhost:5173`)

---

## 3. End-to-End Demonstration Script

Follow this sequential walkthrough to present all KAVACH features safely:

### 1. User Account Registration & Login
1. Click **Register** on the login page.
2. Enter Full Name (e.g. `Demo User`), Email (`demouser@kavach.ai`), and Password (`UserPass@123`).
3. Click **Register** and log in with the new credentials.

### 2. Message Scam Detection Demonstration
1. Open the **Message Scanner** tab.
2. **Safe Test**: Enter `Hey Alex, are we still meeting for lunch at 1 PM today?`
   - *Expected Verdict*: `SAFE` (Risk Score < 35).
3. **Scam Test**: Enter `URGENT! Your bank account is suspended due to unauthorized access. Click http://secure-verify-bank.com immediately to restore access.`
   - *Expected Verdict*: `HIGH RISK` / `SCAM` (Scam probability > 70%, flags high-risk phishing URL & urgency indicators).

### 3. Hybrid URL Scanner Demonstration
1. Open the **Link Checker** tab.
2. **Safe URL Test**: Enter `https://en.wikipedia.org/wiki/Artificial_intelligence`
   - *Expected Verdict*: `SAFE` (Score: 0/100).
3. **Deceptive Phishing URL Test**: Enter `http://login.paypal.com.verify-user-account-security.ru/login`
   - *Expected Verdict*: `HIGH RISK` (Flags raw IP / suspicious domain / excessive subdomains).

### 4. Document & Image Scam Scanner Demonstration
1. Open the **Document Scanner** tab.
2. **Plain Text File Scan**: Upload a `.txt` file containing contract text.
   - *Expected Verdict*: `SAFE` (Native text extraction completed).
3. **Unscannable / Corrupted File**: Upload a corrupted file or blank file.
   - *Expected Verdict*: `UNSCANNABLE` (Warning callout banner displayed; **never marked SAFE**).

### 5. Embedded QR Code Scanner Demonstration
1. Open the **Document Scanner** tab.
2. Upload an image containing a UPI payment QR code or phishing URL QR.
   - *Expected Verdict*: Decodes payload in-memory via OpenCV and flags risk level.

### 6. Guardian Security Feed & Privacy Demonstration
1. Log in as a User, navigate to **Guardian Access**, and generate a 6-digit access code (e.g. `482910`).
2. Log out and select **Guardian Login**. Enter the 6-digit code.
3. Observe the **Guardian Dashboard**:
   - Shows high-level threat alert count and protected status (`SAFE` vs `ATTENTION REQUIRED`).
   - **Privacy Protection**: Confidential message text, OTPs, and private text strings are **strictly omitted** from the guardian view.

### 7. SOC Administrator Dashboard Demonstration
1. Log out and log in using Admin credentials:
   - Email: `admin@kavach.com`
   - Password: `KavachAdmin@123`
2. View **Admin Dashboard**:
   - Monitors system-wide user counts, security scan metrics, threat trends, and active guardian linkages.

---

## 4. Stopping the Application

1. Press `Ctrl + C` in Terminal 1 (FastAPI backend).
2. Press `Ctrl + C` in Terminal 2 (React frontend).
