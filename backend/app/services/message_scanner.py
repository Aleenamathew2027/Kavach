import re
from typing import Any, Dict, List


URGENCY_KEYWORDS = [
    r"\bimmediat(e|ely)\b",
    r"\burgent(ly)?\b",
    r"\bact now\b",
    r"\bwithin (24|12|2|1) hours?\b",
    r"\baccount (will be|has been) (blocked|suspended|terminated|deactivated)\b",
    r"\bfinal (warning|notice)\b",
    r"\blast chance\b",
    r"\bexpire(s|d)? (today|soon|within)\b",
    r"\btime (is running out|sensitive)\b",
    r"\baction required\b",
]

FINANCIAL_KEYWORDS = [
    r"\bsend money\b",
    r"\btransfer (money|funds|amount|cash)\b",
    r"\bbank account\b",
    r"\bwire transfer\b",
    r"\bupi\b",
    r"\bgpay\b",
    r"\bphonepe\b",
    r"\bpaytm\b",
    r"\bqr code\b",
    r"\brefund\b",
    r"\bcash (prize|reward)\b",
    r"\blottery\b",
    r"\bcongratulations,?\s+you (have )?won\b",
    r"\bwon (rs\.?|\$|usd|inr|lakhs?|crores?)\b",
    r"\bclaim (your )?(reward|prize|bonus|money)\b",
    r"\bcrypto(currency)?\b",
    r"\bbitcoin\b",
    r"\bgift card\b",
]

CREDENTIAL_KEYWORDS = [
    r"\bpassword\b",
    r"\botp\b",
    r"\bpin\b",
    r"\bcvv\b",
    r"\bcredit card (number|details)\b",
    r"\bdebit card (number|details)\b",
    r"\bnet ?banking\b",
    r"\bverification code\b",
    r"\benter your (code|otp|pin|password)\b",
    r"\bshare (your )?(otp|code|pin)\b",
    r"\baadhaar( card)?\b",
    r"\bpan( card)?\b",
    r"\blogin (credentials|details)\b",
]

AUTHORITY_IMPERSONATION_KEYWORDS = [
    r"\bpolice\b",
    r"\bcbi\b",
    r"\bcyber (crime|police|cell)\b",
    r"\barrest (warrant)?\b",
    r"\bcourt (order|notice|summons)\b",
    r"\blegal action\b",
    r"\bincome tax\b",
    r"\bcustoms (department|duty|clearance)\b",
    r"\bfedex (parcel|package|shipment)\b",
    r"\btrai\b",
    r"\bmha\b",
    r"\bbank (officer|manager|representative)\b",
    r"\brbi\b",
    r"\bkavach security\b",
    r"\baccount compromised\b",
]

SUSPICIOUS_ACTION_KEYWORDS = [
    r"\bclick (here|the link|below)\b",
    r"\bdownload (the )?attachment\b",
    r"\binstall (the )?apk\b",
    r"\banydesk\b",
    r"\bteamviewer\b",
    r"\bquicksupport\b",
    r"\bcall (immediately|this number|helpline)\b",
    r"\bcall back\b",
]


def analyze_message_text(text: str) -> Dict[str, Any]:
    """
    Rule-based Message Scam Detection Engine.
    Analyzes message content for urgency, financial demands, credential harvesting,
    authority impersonation, and deceptive actions.
    """
    if not text or not text.strip():
        return {
            "risk_level": "SAFE",
            "risk_score": 0,
            "detected_indicators": [],
            "reasons": ["Empty message provided."],
            "recommended_action": "No action needed.",
            "summary": "Empty content analyzed.",
        }

    content = text.strip()
    score = 0
    detected_indicators = []
    reasons = []

    # 1. Check Urgency & Coercion
    urgency_matches = [p for p in URGENCY_KEYWORDS if re.search(p, content, re.IGNORECASE)]
    if urgency_matches:
        score += min(30, 15 + len(urgency_matches) * 5)
        detected_indicators.append("Urgency & Artificial Time Pressure")
        reasons.append("Creates false urgency or threatens account suspension to bypass critical thinking.")

    # 2. Check Financial Requests & Lottery Claims
    financial_matches = [p for p in FINANCIAL_KEYWORDS if re.search(p, content, re.IGNORECASE)]
    if financial_matches:
        score += min(35, 15 + len(financial_matches) * 5)
        detected_indicators.append("Financial Demands / Unverified Prize Claims")
        reasons.append("Requests financial transactions, money transfer, or promises unverified rewards.")

    # 3. Check Credential & Sensitive Data Harvesting
    credential_matches = [p for p in CREDENTIAL_KEYWORDS if re.search(p, content, re.IGNORECASE)]
    if credential_matches:
        score += min(40, 20 + len(credential_matches) * 5)
        detected_indicators.append("Credential & OTP Harvesting Attempt")
        reasons.append("Solicits confidential verification codes, passwords, OTPs, or banking credentials.")

    # 4. Check Authority Impersonation & Legal Threats
    authority_matches = [p for p in AUTHORITY_IMPERSONATION_KEYWORDS if re.search(p, content, re.IGNORECASE)]
    if authority_matches:
        score += min(35, 15 + len(authority_matches) * 5)
        detected_indicators.append("Authority / Law Enforcement Impersonation")
        reasons.append("Claims affiliation with police, customs, bank, or government agencies to intimidate.")

    # 5. Check Suspicious Action Prompts
    action_matches = [p for p in SUSPICIOUS_ACTION_KEYWORDS if re.search(p, content, re.IGNORECASE)]
    if action_matches:
        score += min(25, 10 + len(action_matches) * 5)
        detected_indicators.append("Deceptive Action / Remote Access Prompt")
        reasons.append("Instructs user to click unverified links, install remote access software, or call unknown numbers.")

    # Cap score at 100
    risk_score = min(100, score)

    # Classify Risk Level
    if risk_score >= 50 or (len(detected_indicators) >= 2 and risk_score >= 35):
        risk_level = "HIGH RISK"
        summary = "High probability of scam / fraudulent communication."
        recommended_action = "Do NOT click any links, share OTPs, or transfer money. Block and report the sender immediately."
    elif risk_score >= 20:
        risk_level = "SUSPICIOUS"
        summary = "Contains suspicious language patterns that warrant caution."
        recommended_action = "Exercise caution. Verify with the official entity through an independent channel before proceeding."
    else:
        risk_level = "SAFE"
        summary = "No prominent scam patterns or malicious indicators detected."
        recommended_action = "Standard communication. Always maintain general digital safety hygiene."
        if not reasons:
            reasons.append("Message does not contain known urgency, financial, or credential-harvesting patterns.")

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "detected_indicators": detected_indicators,
        "reasons": reasons,
        "recommended_action": recommended_action,
        "summary": summary,
    }
