# KAVACH — LINK SCAM & PHISHING DETECTION MODULE

## 1. Overview
The Link Safety Checker is a multi-signal static URL analysis engine integrated into the KAVACH AI Security Platform. It allows users to paste any suspicious URL (e.g. `https://example.com` or `http://fake-bank-login.com/verify`) and immediately receive a comprehensive security assessment.

---

## 2. Detection Architecture & Signals Checked
The engine (`backend/app/services/link_scanner.py`) evaluates 20+ independent security signals **statically** without making outgoing HTTP/HTTPS connections (preventing SSRF vulnerabilities and tracking risks):

1. **Protocol Security**: HTTP (unencrypted) vs HTTPS (encrypted).
2. **Raw IP Hostname**: Detects raw numerical IPv4/IPv6 addresses (e.g. `http://192.168.1.1/login`).
3. **Deceptive Userinfo (@ symbol)**: Detects embedded credentials used to disguise the real domain (`https://bank.com@evil.example`).
4. **Punycode / IDN Homographs**: Flags `xn--` internationalized domain encodings used for visual brand spoofing.
5. **URL Shorteners**: Identifies link hiding services (`bit.ly`, `tinyurl.com`, `is.gd`, `cutt.ly`, etc.).
6. **High-Risk TLDs**: Flags low-reputation top-level domains heavily associated with phishing/malware (`.xyz`, `.top`, `.work`, `.click`, `.loan`, `.buzz`, `.zip`, `.mov`, etc.).
7. **Excessive Subdomain Depth**: Identifies deeply nested subdomains (e.g., `login.verify.bank.account.example.com`).
8. **Subdomain Credential Keywords**: Flags sensitive keywords (`login`, `verify`, `kyc`, `otp`) inside subdomains.
9. **Brand Impersonation / Typosquatting**: Matches patterns targeting banking/payment brands (SBI, HDFC, ICICI, Paytm, PayPal, Google, Apple, Netflix, Amazon).
10. **Excessive Domain Hyphenation**: Detects 3+ hyphens in hostnames.
11. **URL Length Anomaly**: Flags URLs exceeding 100 characters.
12. **High Special Character Density**: Counts excessive `@`, `%`, `-`, `_`, `=`, `?`, `&` characters.
13. **Executable Download Targets**: Detects direct executable/script download extensions (`.apk`, `.exe`, `.bat`, `.scr`, `.msi`).
14. **Excessive Path Depth**: Flags paths nested 5+ levels deep.
15. **Sensitive Target Keywords**: Detects credential-gathering terms in path/query parameters.
16. **Open Redirect / Auth Parameters**: Identifies parameters susceptible to token forwarding (`redirect`, `next`, `target`, `token`, `session`).
17. **Non-Standard Network Ports**: Flags web links on non-standard ports (other than 80/443).
18. **Malformed / Invalid Syntax**: Safely catches unparseable or obfuscated URL formats.

---

## 3. Risk Scoring & Classification Thresholds
- **0 – 29 Risk Score**: `SAFE` (Verdict: `SAFE`, Risk Level: `LOW`)
- **30 – 59 Risk Score**: `SUSPICIOUS` (Verdict: `SUSPICIOUS`, Risk Level: `MEDIUM`)
- **60 – 100 Risk Score**: `HIGH RISK` (Verdict: `HIGH RISK`, Risk Level: `HIGH`)

All score calculations accumulate weighted risk points from detected signals (capped at 100).

---

## 4. Heuristic vs Machine Learning Status
- **Current Analysis Engine**: Transparently labeled as **`URL Heuristic Analysis`** (with ~90–96% score confidence).
- **No False ML Claims**: Unlike the message detection module (which uses a trained Logistic Regression model on the SMS Spam dataset), the link module currently relies on multi-signal static analysis. It does NOT claim to use an ML model.

---

## 5. API Endpoint Specifications

### Request
`POST /security/analyze-link`
*Headers*: `Authorization: Bearer <JWT_USER_TOKEN>`
```json
{
    "url": "https://secure-login-example.com@evil.example/verify"
}
```

### Response
```json
{
    "url": "https://secure-login-example.com@evil.example/verify",
    "verdict": "HIGH RISK",
    "risk_level": "HIGH",
    "risk_score": 90,
    "analysis_type": "URL Heuristic Analysis",
    "confidence": 93.5,
    "indicators": [
        "Deceptive @ Userinfo Obfuscation",
        "Brand Impersonation / Phishing Typosquatting",
        "Login & Verification Target Keywords"
    ],
    "detected_indicators": [
        "Deceptive @ Userinfo Obfuscation",
        "Brand Impersonation / Phishing Typosquatting",
        "Login & Verification Target Keywords"
    ],
    "reasons": [
        "Uses standard HTTPS protocol encryption.",
        "Contains an '@' symbol in the authority block, often used to disguise the actual destination server.",
        "Domain or path mimics well-known banking, payment, or cloud service identity."
    ],
    "recommendation": "DO NOT OPEN THIS LINK. Do not enter passwords, OTPs, banking information, or personal details.",
    "recommended_action": "DO NOT OPEN THIS LINK. Do not enter passwords, OTPs, banking information, or personal details.",
    "summary": "Potential phishing, deceptive spoofing, or malicious URL detected.",
    "scan_id": 42,
    "alert_created": true
}
```

---

## 6. Database Logging & Guardian Alert System
1. Every link analysis creates a record in `SecurityScan` (`scan_type="link"`, `risk_level`, `risk_score`, `detected_indicators`, `result_summary`).
2. When a link is classified as `HIGH RISK`:
   - A `SecurityAlert` is automatically created in PostgreSQL (`alert_type="link_scam"`, `severity="HIGH"`).
   - If the user has granted access to a Guardian, the alert automatically streams to the Guardian's dashboard and alerts feed.

---

## 7. Future ML URL Model Training Roadmap
To add a dedicated Machine Learning model for URL Phishing Detection in the future:
1. **Dataset**: Acquire a benchmark URL phishing dataset (e.g. PhishTank, ISCX-URL2016, or Kaggle Malicious URLs dataset with 400k+ URLs).
2. **Feature Extraction**: Extract lexical features (URL length, domain length, character entropy, TLD frequency, n-grams) into `backend/app/ai/link_detector.py`.
3. **Training**: Train Random Forest / LightGBM or Character-level CNN model and save pipeline weights to `models/link_detector/`.
4. **Integration**: Combine ML prediction probability with heuristic rules (similar to `predict_message_scam` in `backend/app/ai/message_detector.py`).

---

## 8. Automated Testing Instructions
Run unit tests for link scanner:
```powershell
cd backend
.\venv\Scripts\python.exe test_link_scanner.py
```

Run complete role isolation and auth test suite:
```powershell
.\venv\Scripts\python.exe test_auth_rbac.py
.\venv\Scripts\python.exe test_role_isolation.py
```
