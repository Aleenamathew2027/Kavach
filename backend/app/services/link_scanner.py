import ipaddress
import re
import logging
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from app.ai.url_detector import predict_url_phishing

logger = logging.getLogger("kavach.services.link_scanner")

# Configuration Weights for Hybrid Score Engine
HEURISTIC_WEIGHT = 0.50
ML_WEIGHT = 0.50

# Common URL Shortener Services
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "adf.ly", "bit.do", "soo.gd",
    "tiny.cc", "lnk.to", "s.id", "v.gd", "bc.vc", "q.gs"
}

# High-Risk / Low-Reputation Top Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".loan", ".buzz", ".fit",
    ".gq", ".cf", ".tk", ".ml", ".ga", ".cc", ".to", ".pw", ".bid",
    ".zip", ".mov", ".country", ".stream", ".download", ".racing",
    ".party", ".review", ".science", ".date", ".faith", ".accountant"
}

# Brand Impersonation Regex Patterns
IMPERSONATION_PATTERNS = [
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
    r"secure(-|\.)?(login|banking|verification|update|auth|portal)",
]

# Sensitive / Credential Keyword Indicators
SENSITIVE_KEYWORDS = [
    "login", "signin", "verify", "verification", "auth", "authenticate",
    "password", "passcode", "account", "update", "banking", "netbanking",
    "kyc", "otp", "pin", "credential", "security-check", "confirm",
    "wallet", "billing", "recharge", "claim", "reward", "winner"
]

# Suspicious Path Extensions (Executables, Installers, Scripts)
SUSPICIOUS_PATH_EXTENSIONS = [
    r"\.apk$", r"\.exe$", r"\.scr$", r"\.bat$", r"\.vbs$", r"\.iso$",
    r"\.msi$", r"\.cmd$", r"\.ps1$", r"\.jar$", r"\.dmg$"
]

# Suspicious Query Parameter Keys
SUSPICIOUS_QUERY_PARAMS = [
    "redirect", "next", "url", "destination", "target", "token", "session",
    "auth", "login", "cmd", "return_to", "goto"
]


def _analyze_heuristic_signals(raw_input: str) -> Dict[str, Any]:
    """
    Static Multi-Signal URL Security Heuristics.
    Evaluates 20+ URL structural anomalies, protocol security, brand typosquatting, etc.
    """
    # Check for invalid spaces or control characters in raw URL input before normalization
    if re.search(r"[\s\t\n\r]", raw_input):
        return {
            "score": 90,
            "indicators": ["Malformed URL Syntax"],
            "reasons": ["The URL contains invalid spaces or unescaped control characters."],
        }

    normalized_url = raw_input
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", normalized_url):
        normalized_url = "https://" + normalized_url

    try:
        parsed = urlparse(normalized_url)
    except Exception as e:
        return {
            "score": 90,
            "indicators": ["Malformed URL Syntax"],
            "reasons": [f"URL could not be parsed safely: {str(e)}"],
        }

    hostname = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    if not hostname:
        return {
            "score": 85,
            "indicators": ["Missing Domain / Hostname"],
            "reasons": ["The URL lacks a valid domain name or IP hostname."],
        }

    score = 0
    indicators: List[str] = []
    reasons: List[str] = []

    # 1. Protocol Security
    if scheme == "http":
        score += 15
        indicators.append("Unencrypted HTTP Protocol")
        reasons.append("Uses unencrypted HTTP instead of encrypted HTTPS.")
    elif scheme == "https":
        reasons.append("Uses standard HTTPS protocol encryption.")

    # 2. IP Address as Hostname
    is_ip_address = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if is_ip_address:
        score += 45
        indicators.append("Raw IP Address Hostname")
        reasons.append(f"Destination hostname points directly to a raw IP address ({hostname}) rather than a verified domain.")

    # 3. Embedded Credentials / @ Symbol
    if "@" in netloc:
        score += 45
        indicators.append("Deceptive @ Userinfo Obfuscation")
        reasons.append("Contains an '@' symbol in the authority block, often used to disguise the actual destination server.")

    # 4. Punycode Domain
    if "xn--" in hostname:
        score += 35
        indicators.append("Punycode / IDN Homograph Risk")
        reasons.append("Uses Punycode (xn--) encoding which can spoof legitimate brand domain characters.")

    # 5. URL Shortener
    if hostname in SHORTENERS or any(hostname.endswith("." + s) for s in SHORTENERS):
        score += 25
        indicators.append("URL Shortener / Obfuscation Service")
        reasons.append(f"Uses shortener service '{hostname}' which hides the final destination URL.")

    # 6. High-Risk TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 30
            indicators.append("High-Risk / Low-Reputation TLD")
            reasons.append(f"Domain uses top-level domain '{tld}' heavily associated with phishing and spam.")
            break

    # 7. Excessive Subdomain Depth
    subparts = [p for p in hostname.split(".") if p]
    if not is_ip_address and len(subparts) > 4:
        score += 20
        indicators.append("Excessive Subdomain Depth")
        reasons.append(f"Hostname contains {len(subparts)-2} subdomain levels, often used to conceal real domain owner.")

    # 8. Subdomain Credential Keywords
    if not is_ip_address and len(subparts) > 2:
        subdomain_str = ".".join(subparts[:-2])
        found_sub_kw = [kw for kw in SENSITIVE_KEYWORDS if kw in subdomain_str]
        if found_sub_kw:
            score += 25
            indicators.append("Subdomain Credential Keyword Targeting")
            reasons.append(f"Subdomain contains sensitive credential keywords ({', '.join(found_sub_kw[:3])}).")

    # 9. Brand Impersonation / Typosquatting
    impersonation_matches = []
    for pat in IMPERSONATION_PATTERNS:
        if re.search(pat, hostname) or re.search(pat, path.lower()):
            impersonation_matches.append(pat)

    if impersonation_matches:
        score += 40
        indicators.append("Brand Impersonation / Phishing Typosquatting")
        reasons.append("Domain or path mimics well-known banking, payment, or cloud service identity.")

    # 10. Excessive Hyphens
    if hostname.count("-") >= 3:
        score += 20
        indicators.append("Excessive Domain Hyphenation")
        reasons.append("Domain hostname uses multiple hyphens, a common pattern in spoofed landing sites.")

    # 11. Excessive URL Length
    if len(raw_input) > 100:
        score += 15
        indicators.append("Excessive URL Length")
        reasons.append(f"URL is unusually long ({len(raw_input)} characters), often used to hide deceptive tokens.")

    # 12. High Special Character Density
    special_char_count = sum(raw_input.count(c) for c in ["@", "%", "-", "_", "=", "?", "&", "$", "!"])
    if special_char_count >= 10:
        score += 15
        indicators.append("High Special Character Density")
        reasons.append(f"Contains high count of special characters ({special_char_count}), indicating heavy parameter wrapping or obfuscation.")

    # 13. Executable / APK Downloads
    for ext_pat in SUSPICIOUS_PATH_EXTENSIONS:
        if re.search(ext_pat, path, re.IGNORECASE):
            score += 50
            indicators.append("Executable / Mobile Package Download Target")
            reasons.append("URL path points directly to an executable file or installer package (.apk, .exe, .bat).")
            break

    # 14. Excessive Path Depth
    path_segments = [s for s in path.split("/") if s]
    if len(path_segments) >= 5:
        score += 15
        indicators.append("Excessive Path Segment Depth")
        reasons.append(f"Deeply nested URL path structure ({len(path_segments)} segments).")

    # 15. Sensitive Target Keywords
    path_query_lower = (path + "?" + query).lower()
    found_path_kws = [kw for kw in SENSITIVE_KEYWORDS if kw in path_query_lower]
    if found_path_kws:
        score += 15
        indicators.append("Login & Verification Target Keywords")
        reasons.append(f"URL path or query parameters target sensitive actions ({', '.join(found_path_kws[:3])}).")

    # 16. Open Redirect / Auth Parameters
    if query:
        parsed_query = parse_qs(query)
        suspicious_params_found = [p for p in parsed_query.keys() if p.lower() in SUSPICIOUS_QUERY_PARAMS]
        if suspicious_params_found:
            score += 15
            indicators.append("Suspicious Open Redirect / Auth Parameters")
            reasons.append(f"Contains parameters susceptible to open redirects or token forwarding ({', '.join(suspicious_params_found[:3])}).")

    # 17. Non-Standard Port Specification
    if parsed.port and parsed.port not in (80, 443):
        score += 20
        indicators.append("Non-Standard Web Port")
        reasons.append(f"URL uses non-standard network port :{parsed.port}.")

    final_h_score = max(0, min(100, score))

    return {
        "score": final_h_score,
        "indicators": indicators,
        "reasons": reasons,
    }


def analyze_link_url(url: str) -> Dict[str, Any]:
    """
    Hybrid Layered URL Security Engine for Kavach.

    Combines:
      1. Multi-signal static rule heuristics (20+ URL threat indicators)
      2. ML URL Phishing Detector (Random Forest trained on ISCX Phishing Benchmark)

    Returns combined risk score (0-100), verdict, ML probabilities, indicators,
    and action recommendations.
    """
    if not url or not url.strip():
        return {
            "url": url or "",
            "verdict": "SAFE",
            "risk_level": "LOW",
            "risk_score": 0,
            "analysis_type": "Hybrid URL Security Engine (Heuristic + ML)",
            "confidence": 95.0,
            "heuristic_score": 0,
            "ml_verdict": "SAFE",
            "ml_confidence": 100.0,
            "ml_phishing_probability": 0.0,
            "ml_safe_probability": 100.0,
            "model": "Random Forest Classifier",
            "model_scope": "ISCX Phishing Benchmark",
            "indicators": [],
            "detected_indicators": [],
            "reasons": ["Empty or whitespace-only URL provided."],
            "recommendation": "Please enter a valid URL to run safety inspection.",
            "recommended_action": "Please enter a valid URL to run safety inspection.",
            "summary": "No URL content to analyze.",
        }

    raw_input = url.strip()

    # 1. Primary ML URL Inference
    try:
        ml_res = predict_url_phishing(raw_input)
        ml_pred = ml_res.get("prediction", "SAFE")
        ml_phish_prob = float(ml_res.get("phishing_probability", 0.0))
        ml_safe_prob = float(ml_res.get("safe_probability", 100.0))
        ml_conf = float(ml_res.get("confidence", 90.0))
        model_name = ml_res.get("model", "Random Forest Classifier")
        model_scope = ml_res.get("model_scope", "ISCX Phishing Benchmark")
    except Exception as ml_err:
        logger.error(f"ML URL Detector Error: {ml_err}", exc_info=True)
        ml_pred = "SAFE"
        ml_phish_prob = 0.0
        ml_safe_prob = 100.0
        ml_conf = 50.0
        model_name = "Rule Heuristics Fallback"
        model_scope = "Heuristic Analysis"

    # 2. Secondary Static Rule Heuristic Analysis
    h_res = _analyze_heuristic_signals(raw_input)
    heuristic_score = h_res["score"]
    indicators = list(h_res["indicators"])
    reasons = list(h_res["reasons"])

    # 3. Layered Combined Scoring Engine
    ml_score = int(round(ml_phish_prob))
    combined_score = int(round(heuristic_score * HEURISTIC_WEIGHT + ml_score * ML_WEIGHT))

    # Critical threat floor/ceiling overrides
    if heuristic_score >= 75 or (ml_pred == "PHISHING" and heuristic_score >= 35) or ml_phish_prob >= 85:
        final_score = max(combined_score, 65)
    elif ml_pred == "PHISHING" or heuristic_score >= 30 or combined_score >= 30:
        final_score = max(combined_score, 35)
    else:
        final_score = combined_score

    final_score = max(0, min(100, final_score))

    # 4. Final Verdict & Risk Level Mapping
    if final_score >= 60:
        verdict = "HIGH RISK"
        risk_level = "HIGH"
        summary = f"High-risk phishing / malicious URL detected by Hybrid Engine ({model_name} phishing prob: {ml_phish_prob:.1f}%)."
        recommendation = "DO NOT OPEN THIS LINK. Do not enter passwords, OTPs, banking information, or personal details."
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
        risk_level = "MEDIUM"
        summary = f"Suspicious URL flagged by Hybrid Engine ({model_name} phishing prob: {ml_phish_prob:.1f}%)."
        recommendation = "Exercise caution. Verify the legitimate domain directly before entering sensitive data."
    else:
        verdict = "SAFE"
        risk_level = "LOW"
        summary = f"URL classified as SAFE by Hybrid Engine ({model_name} confidence: {ml_conf:.1f}%)."
        recommendation = "The URL appears low risk. Always verify site security certificates before entering credentials."

    # Prepend ML model explanation to reasons list
    ml_explanation = f"AI Model ({model_name}): Classified as {ml_pred} with {ml_conf:.1f}% confidence ({ml_phish_prob:.1f}% phishing probability)."
    reasons.insert(0, ml_explanation)

    if verdict == "SAFE" and len(reasons) <= 1:
        reasons.append("Standard domain structure with HTTPS encryption and no flagged anomalies.")

    combined_confidence = round((ml_conf + (92.0 + min(6.0, len(indicators) * 1.5))) / 2.0, 1)

    return {
        "url": raw_input,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": final_score,
        "heuristic_score": heuristic_score,
        "analysis_type": "Hybrid URL Security Engine (Heuristic + ML)",
        "confidence": combined_confidence,
        # ML Breakdown
        "ml_verdict": ml_pred,
        "ml_confidence": ml_conf,
        "ml_phishing_probability": ml_phish_prob,
        "ml_safe_probability": ml_safe_prob,
        "model": model_name,
        "model_scope": model_scope,
        # Indicators & Guidance
        "indicators": indicators,
        "detected_indicators": indicators,
        "reasons": reasons,
        "recommendation": recommendation,
        "recommended_action": recommendation,
        "summary": summary,
    }
