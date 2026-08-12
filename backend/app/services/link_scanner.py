import re
from typing import Any, Dict, List
from urllib.parse import urlparse


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "adf.ly", "bit.do", "soo.gd"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".loan", ".buzz", ".fit",
    ".gq", ".cf", ".tk", ".ml", ".ga", ".cc", ".to", ".pw", ".bid"
}

IMPERSONATION_PATTERNS = [
    r"sbi(-|\.)?(online|bank|secure|login|verify)",
    r"hdfc(-|\.)?(netbanking|secure|verify|update)",
    r"icici(-|\.)?(bank|secure|login)",
    r"paytm(-|\.)?(kyc|reward|cash|verify)",
    r"paypal(-|\.)?(security|verify|account|update)",
    r"google(-|\.)?(drive|verify|login|docs-secure)",
    r"apple(-|\.)?(id|support|icloud-verify)",
    r"netflix(-|\.)?(billing|payment|account-update)",
    r"amazon(-|\.)?(gift|reward|order-update)",
    r"secure(-|\.)?(login|banking|verification|update)",
]

SUSPICIOUS_PATH_EXTENSIONS = [
    r"\.apk$", r"\.exe$", r"\.scr$", r"\.bat$", r"\.vbs$", r"\.iso$", r"\.msi$"
]


def analyze_link_url(url: str) -> Dict[str, Any]:
    """
    Rule-based Link & URL Safety Scanner.
    Safely analyzes URL structure, domain reputation, protocol security,
    typosquatting, and deceptive patterns without executing or opening the URL.
    """
    if not url or not url.strip():
        return {
            "url": url,
            "risk_level": "SAFE",
            "risk_score": 0,
            "detected_indicators": [],
            "reasons": ["Empty URL provided."],
            "recommended_action": "Enter a valid URL to analyze.",
            "summary": "No content analyzed.",
        }

    raw_url = url.strip()

    # Prepend scheme if missing for clean parsing
    if not re.match(r"^[a-zA-Z]+://", raw_url):
        raw_url = "https://" + raw_url

    try:
        parsed = urlparse(raw_url)
    except Exception:
        return {
            "url": url,
            "risk_level": "HIGH RISK",
            "risk_score": 90,
            "detected_indicators": ["Malformed URL Format"],
            "reasons": ["The URL has an invalid syntax or deceptive character encoding."],
            "recommended_action": "Do NOT open this link. It appears malformed or deliberately obfuscated.",
            "summary": "Malformed or unparseable URL.",
        }

    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_str = raw_url.lower()

    score = 0
    detected_indicators = []
    reasons = []

    # 1. Check Protocol (HTTP vs HTTPS)
    if parsed.scheme == "http":
        score += 15
        detected_indicators.append("Unencrypted Insecure HTTP Protocol")
        reasons.append("The link uses unencrypted HTTP instead of secure HTTPS.")

    # 2. Check for IP Address in Hostname
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, hostname):
        score += 45
        detected_indicators.append("Raw IP Address Hostname")
        reasons.append("The link points directly to a raw numerical IP address rather than a verified domain name.")

    # 3. Check for URL Shorteners
    if hostname in SHORTENERS or any(hostname.endswith("." + s) for s in SHORTENERS):
        score += 25
        detected_indicators.append("URL Shortener / Obfuscation Service")
        reasons.append("The link uses a URL shortener which hides the true destination server.")

    # 4. Check for High-Risk Top-Level Domains (TLDs)
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 30
        detected_indicators.append("High-Risk / Low-Reputation TLD")
        reasons.append("The domain uses a top-level domain frequently associated with spam, phishing, and malware.")

    # 5. Check for Brand Impersonation / Typosquatting
    impersonation_found = False
    for pat in IMPERSONATION_PATTERNS:
        if re.search(pat, hostname) or re.search(pat, path):
            impersonation_found = True
            break

    if impersonation_found:
        score += 45
        detected_indicators.append("Brand Impersonation / Phishing Typosquatting")
        reasons.append("The domain contains keywords mimicking well-known banking, payment, or tech services.")

    # 6. Check for Excessive Subdomains
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) > 4:
        score += 20
        detected_indicators.append("Excessive Nested Subdomains")
        reasons.append("Contains unusually deep subdomain nesting designed to disguise the actual parent domain.")

    # 7. Check for Embedded Credentials / At-sign (@) in URL
    if "@" in parsed.netloc:
        score += 40
        detected_indicators.append("Deceptive Userinfo / @ Symbol in URL")
        reasons.append("Uses an '@' symbol in the URL to trick users about the actual destination hostname.")

    # 8. Check for Malicious Executable/Script Extensions in Path
    for ext_pat in SUSPICIOUS_PATH_EXTENSIONS:
        if re.search(ext_pat, path):
            score += 50
            detected_indicators.append("Direct Executable / APK Download Target")
            reasons.append("Points directly to a downloadable executable file, script, or mobile APK package.")

    # 9. Check for Multiple Hyphens in Domain (common in fake phishing landing pages)
    if hostname.count("-") >= 3:
        score += 20
        detected_indicators.append("Excessive Hyphenated Domain Name")
        reasons.append("The domain uses multiple hyphens, a common characteristic of spoofed landing pages.")

    risk_score = min(100, score)

    # Classify Risk Level
    if risk_score >= 50 or (len(detected_indicators) >= 2 and risk_score >= 35):
        risk_level = "HIGH RISK"
        summary = "High probability of malicious / phishing URL."
        recommended_action = "Do NOT open this link or enter any information. Block the sender and report the URL."
    elif risk_score >= 20:
        risk_level = "SUSPICIOUS"
        summary = "The link exhibits potential risk factors or hides its destination."
        recommended_action = "Do not open this URL directly. Verify the source or use an independent search to find the official website."
    else:
        risk_level = "SAFE"
        summary = "No known deceptive or malicious patterns detected."
        recommended_action = "The URL format appears standard. Always verify security certificates before entering credentials."
        if not reasons:
            reasons.append("Standard HTTPS domain with recognized structure and no deceptive subdomains.")

    return {
        "url": url,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "detected_indicators": detected_indicators,
        "reasons": reasons,
        "recommended_action": recommended_action,
        "summary": summary,
    }
