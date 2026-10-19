"""
=============================================================================
KAVACH AI — URL Lexical Feature Extractor
=============================================================================
Reusable, zero-data-leakage feature extractor for URL Phishing Classification.
Transforms raw URL strings into numerical feature vectors for ML model training
and inference.
=============================================================================
"""

import ipaddress
import re
from typing import Any, Dict, List, Union
from urllib.parse import parse_qs, urlparse
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "adf.ly", "bit.do", "soo.gd",
    "tiny.cc", "lnk.to", "s.id", "v.gd", "bc.vc", "q.gs"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".loan", ".buzz", ".fit",
    ".gq", ".cf", ".tk", ".ml", ".ga", ".cc", ".to", ".pw", ".bid",
    ".zip", ".mov", ".country", ".stream", ".download", ".racing",
    ".party", ".review", ".science", ".date", ".faith", ".accountant"
}

BRAND_PATTERNS = [
    r"sbi(-|\.)?(online|bank|secure|login|verify|netbanking|update|kyc)",
    r"hdfc(-|\.)?(netbanking|secure|verify|update|bank|login)",
    r"icici(-|\.)?(bank|secure|login|netbanking|verify)",
    r"paytm(-|\.)?(kyc|reward|cash|verify|login|wallet)",
    r"paypal(-|\.)?(security|verify|account|update|login|checkout)",
    r"google(-|\.)?(drive|verify|login|docs-secure|account|support)",
    r"apple(-|\.)?(id|support|icloud-verify|login|authorize)",
    r"netflix(-|\.)?(billing|payment|account-update|verify|member)",
    r"amazon(-|\.)?(gift|reward|order-update|prime-verify|login)",
    r"microsoft(-|\.)?(login|office365|verify|account|security)",
    r"meta(-|\.)?(facebook|instagram|support-verify|security-check)",
]

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_slashes",
    "count_question_marks",
    "count_ampersands",
    "count_equals",
    "count_at",
    "count_percent",
    "count_digits",
    "ratio_digits_url",
    "ratio_digits_host",
    "subdomain_count",
    "is_https",
    "is_http",
    "is_ip_address",
    "has_at_symbol",
    "has_shortener",
    "has_suspicious_tld",
    "has_punycode",
    "has_executable",
    "has_login_kw",
    "has_verify_kw",
    "has_bank_kw",
    "has_account_kw",
    "has_pay_kw",
    "has_secure_kw",
    "brand_impersonation",
]


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible Feature Extractor for URLs.
    Extracts 32 numeric features from raw URL strings.
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES

    def fit(self, X, y=None):
        return self

    @staticmethod
    def extract_single_url_features(url: str) -> List[float]:
        """Extracts 32 numerical features from a single raw URL string."""
        if not isinstance(url, str) or not url.strip():
            return [0.0] * len(FEATURE_NAMES)

        raw_url = url.strip()
        normalized_url = raw_url
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", normalized_url):
            normalized_url = "https://" + normalized_url

        try:
            parsed = urlparse(normalized_url)
        except Exception:
            # Fallback for malformed URLs
            return [float(len(raw_url))] + [0.0] * (len(FEATURE_NAMES) - 1)

        hostname = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        full_lower = raw_url.lower()

        url_length = len(raw_url)
        hostname_length = len(hostname)
        path_length = len(path)
        query_length = len(query)

        count_dots = raw_url.count(".")
        count_hyphens = raw_url.count("-")
        count_underscores = raw_url.count("_")
        count_slashes = raw_url.count("/")
        count_question_marks = raw_url.count("?")
        count_ampersands = raw_url.count("&")
        count_equals = raw_url.count("=")
        count_at = raw_url.count("@")
        count_percent = raw_url.count("%")

        digits_in_url = sum(c.isdigit() for c in raw_url)
        digits_in_host = sum(c.isdigit() for c in hostname)
        ratio_digits_url = round(digits_in_url / max(1, url_length), 4)
        ratio_digits_host = round(digits_in_host / max(1, hostname_length), 4)

        subparts = [p for p in hostname.split(".") if p]
        subdomain_count = max(0, len(subparts) - 2) if len(subparts) >= 2 else 0

        is_https = 1.0 if scheme == "https" else 0.0
        is_http = 1.0 if scheme == "http" else 0.0

        is_ip = 0.0
        try:
            ipaddress.ip_address(hostname)
            is_ip = 1.0
        except ValueError:
            is_ip = 0.0

        has_at_symbol = 1.0 if "@" in netloc or "@" in raw_url else 0.0

        has_shortener = 1.0 if (hostname in SHORTENERS or any(hostname.endswith("." + s) for s in SHORTENERS)) else 0.0
        has_suspicious_tld = 1.0 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0
        has_punycode = 1.0 if "xn--" in hostname else 0.0

        executable_exts = [r"\.apk$", r"\.exe$", r"\.bat$", r"\.scr$", r"\.msi$", r"\.vbs$"]
        has_executable = 1.0 if any(re.search(ext, path, re.IGNORECASE) for ext in executable_exts) else 0.0

        has_login_kw = 1.0 if any(k in full_lower for k in ["login", "signin"]) else 0.0
        has_verify_kw = 1.0 if any(k in full_lower for k in ["verify", "verification"]) else 0.0
        has_bank_kw = 1.0 if any(k in full_lower for k in ["bank", "banking", "netbanking"]) else 0.0
        has_account_kw = 1.0 if any(k in full_lower for k in ["account", "update"]) else 0.0
        has_pay_kw = 1.0 if any(k in full_lower for k in ["pay", "payment", "kyc", "otp", "card", "billing"]) else 0.0
        has_secure_kw = 1.0 if any(k in full_lower for k in ["secure", "auth", "portal"]) else 0.0

        brand_impersonation = 1.0 if any(re.search(pat, hostname) or re.search(pat, path.lower()) for pat in BRAND_PATTERNS) else 0.0

        return [
            float(url_length),
            float(hostname_length),
            float(path_length),
            float(query_length),
            float(count_dots),
            float(count_hyphens),
            float(count_underscores),
            float(count_slashes),
            float(count_question_marks),
            float(count_ampersands),
            float(count_equals),
            float(count_at),
            float(count_percent),
            float(digits_in_url),
            ratio_digits_url,
            ratio_digits_host,
            float(subdomain_count),
            is_https,
            is_http,
            is_ip,
            has_at_symbol,
            has_shortener,
            has_suspicious_tld,
            has_punycode,
            has_executable,
            has_login_kw,
            has_verify_kw,
            has_bank_kw,
            has_account_kw,
            has_pay_kw,
            has_secure_kw,
            brand_impersonation,
        ]

    def transform(self, X, y=None) -> np.ndarray:
        """Transforms a list/Series of URL strings into a 2D feature matrix."""
        if isinstance(X, (pd.Series, pd.DataFrame)):
            urls = X.values.flatten()
        elif isinstance(X, np.ndarray):
            urls = X.flatten()
        else:
            urls = list(X)

        matrix = [self.extract_single_url_features(str(u)) for u in urls]
        return np.array(matrix, dtype=np.float64)
