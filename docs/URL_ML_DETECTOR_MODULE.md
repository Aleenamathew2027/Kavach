# KAVACH — MACHINE LEARNING URL PHISHING DETECTOR MODULE

## 1. Overview & Problem Statement
The URL Phishing Detector is the second machine learning security component in the **KAVACH** AI Security Platform. It complements the existing static heuristic scanner by deploying a trained **Random Forest Classifier** trained on 32 lexical URL features to identify stealthy phishing URLs and brand impersonation attacks.

---

## 2. Dataset Specification
- **Dataset**: ISCX Phishing Website Benchmark Dataset
- **Source**: Public research dataset (`datasets/url_detection/dataset_phishing.csv`)
- **Total Samples**: 11,430 rows
- **Clean Unique Samples**: 11,429 rows (1 duplicate URL removed during preprocessing)
- **Class Distribution**:
  - `SAFE` (Legitimate): 5,715 samples (50.0%)
  - `PHISHING` (Malicious): 5,714 samples (50.0%)
- **Missing Values**: 0 missing values
- **Data Leakage Prevention**: Stratified 80/20 train/test split (`random_state=42`). Feature fit performed exclusively on the training split.

---

## 3. Lexical URL Feature Engineering (32 Features)
The reusable `URLFeatureExtractor` (`backend/app/ai/url_feature_extractor.py`) extracts 32 numerical features:

1. `url_length`: Character length of full URL
2. `hostname_length`: Character length of domain hostname
3. `path_length`: Length of path string
4. `query_length`: Length of query parameters string
5. `count_dots`: Count of `.` characters
6. `count_hyphens`: Count of `-` characters
7. `count_underscores`: Count of `_` characters
8. `count_slashes`: Count of `/` characters
9. `count_question_marks`: Count of `?` characters
10. `count_ampersands`: Count of `&` characters
11. `count_equals`: Count of `=` characters
12. `count_at`: Count of `@` characters
13. `count_percent`: Count of `%` characters
14. `count_digits`: Total numeric digits in URL
15. `ratio_digits_url`: Ratio of digits to URL length
16. `ratio_digits_host`: Ratio of digits to hostname length
17. `subdomain_count`: Number of subdomain levels
18. `is_https`: Binary flag (1 if HTTPS, 0 if not)
19. `is_http`: Binary flag (1 if HTTP, 0 if not)
20. `is_ip_address`: Binary flag (1 if numerical IPv4/IPv6 hostname)
21. `has_at_symbol`: Binary flag (1 if `@` in authority block)
22. `has_shortener`: Binary flag for URL shorteners (`bit.ly`, `tinyurl.com`, `cutt.ly`, etc.)
23. `has_suspicious_tld`: Binary flag for high-risk TLDs (`.xyz`, `.top`, `.work`, `.click`, `.loan`, `.zip`, `.mov`, etc.)
24. `has_punycode`: Binary flag for Punycode (`xn--`) IDN homographs
25. `has_executable`: Binary flag for executable/mobile installers (`.apk`, `.exe`, `.bat`, `.scr`, `.msi`)
26–31. `has_login_kw`, `has_verify_kw`, `has_bank_kw`, `has_account_kw`, `has_pay_kw`, `has_secure_kw`: Binary flags for credential targeting keywords
32. `brand_impersonation`: Binary flag for banking & cloud brand spoofing (SBI, HDFC, ICICI, Paytm, PayPal, Google, Apple, Netflix, Amazon)

---

## 4. Candidate Model Comparison & Selection

All models evaluated on the held-out 2,286 test set using `random_state=42`:

| Candidate Model | Accuracy | Precision | Phishing Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 79.53% | 82.80% | 74.54% | 78.45% |
| **Gradient Boosting** | 85.26% | 88.02% | 81.63% | 84.70% |
| **Random Forest (Selected)** | **86.75%** | **87.77%** | **85.39%** | **86.56%** |

### Selected Model
**Random Forest Classifier** was selected due to its superior **Phishing Recall (85.39%)** and **F1-Score (86.56%)**, ensuring minimal false negatives for malicious URLs.

---

## 5. Persisted Artifacts
Saved under `models/url_detector/`:
- `url_model.joblib`: Trained Random Forest weights
- `url_feature_extractor.joblib`: Fitted `URLFeatureExtractor` instance
- `model_metadata.json`: Full evaluation statistics, hyperparameters, dataset metrics

---

## 6. Hybrid Layered Architecture
```
                         URL
                          |
               +----------+----------+
               |                     |
               v                     v
      Static Heuristics      ML URL Detector
      (20+ Signals)          (Random Forest)
               |                     |
         Heuristic Score       Phishing Prob %
               |                     |
               +----------+----------+
                          |
                          v
                 KAVACH Hybrid Engine
               (50% Weight / 50% Weight)
                          |
                          v
                  Final Risk Score (0-100)
                          |
               +----------+----------+
               |          |          |
              SAFE    SUSPICIOUS   HIGH RISK
```

- **Configurable Weights**: `HEURISTIC_WEIGHT = 0.50`, `ML_WEIGHT = 0.50`
- **Threat Floor Overrides**: Ensures high-risk static signals (like raw IP, `@` obfuscation, `.apk` downloads) maintain high risk scores even if ML probability is low.

---

## 7. API Endpoint & Response Schema

`POST /security/analyze-link`
```json
{
  "url": "http://example-login.com/verify",
  "verdict": "HIGH RISK",
  "risk_level": "HIGH",
  "risk_score": 69,
  "heuristic_score": 45,
  "analysis_type": "Hybrid URL Security Engine (Heuristic + ML)",
  "confidence": 91.5,
  "ml_verdict": "PHISHING",
  "ml_confidence": 93.0,
  "ml_phishing_probability": 93.0,
  "ml_safe_probability": 7.0,
  "model": "Random Forest Classifier",
  "model_scope": "ISCX Phishing Benchmark",
  "indicators": [
    "Unencrypted HTTP Protocol",
    "Login & Verification Target Keywords"
  ],
  "reasons": [
    "AI Model (Random Forest Classifier): Classified as PHISHING with 93.0% confidence (93.0% phishing probability).",
    "Uses unencrypted HTTP instead of encrypted HTTPS.",
    "URL path or query parameters target sensitive actions (login, verify)."
  ],
  "recommendation": "DO NOT OPEN THIS LINK. Do not enter passwords, OTPs, banking information, or personal details.",
  "scan_id": 44,
  "alert_created": true
}
```

---

## 8. Security & SSRF Protection
- **Zero Server-Side Network Calls**: The backend analyzes raw URL strings using static regex and lexical parsing. It NEVER fetches web pages, follows HTTP redirects, downloads external payloads, or executes JavaScript server-side.

---

## 9. Testing Instructions
Run ML & Hybrid URL Detector Test Suite:
```powershell
cd backend
.\venv\Scripts\python.exe test_url_detector.py
```

Run Full KAVACH Test Suite:
```powershell
.\venv\Scripts\python.exe test_link_scanner.py
.\venv\Scripts\python.exe test_auth_rbac.py
.\venv\Scripts\python.exe test_role_isolation.py
```
