"""
=============================================================================
KAVACH — Live Voice Real-Time Scam & Vishing Risk Analysis Service
=============================================================================
Performs semantic and heuristic risk analysis on live speech transcript chunks.
Supports:
  - English
  - Malayalam (Script)
  - Malayalam + English Mixed Speech (Manglish & Code-switched)

Produces an explainable risk score (0-100) and actionable safety advisories.
=============================================================================
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("kavach.services.live_voice_risk")

# ---------------------------------------------------------------------------
# PATTERN DEFINITIONS: ENGLISH, MALAYALAM SCRIPT, & MANGLISH TRANSLITERATION
# ---------------------------------------------------------------------------

# 1. Credential & OTP Harvesting (High weight)
CREDENTIAL_PATTERNS = [
    # English
    r"\botp\b",
    r"\bone time password\b",
    r"\bverification code\b",
    r"\bsecurity code\b",
    r"\b(atm |upi |secret )?pin( number)?\b",
    r"\bpassword\b",
    r"\bcvv( number)?\b",
    r"\bcard expiry\b",
    r"\bnet ?banking (password|details)\b",
    r"\bshare (the |your )?(otp|code|pin)\b",
    r"\bgive (me )?(the |your )?otp\b",
    r"\btell (me )?(the |your )?otp\b",
    r"\bread (me )?(the |your )?otp\b",
    r"\bforward (the )?(otp|code)\b",
    r"\baadhaar( card)?\b",
    r"\bpan card( number)?\b",

    # Malayalam Script
    r"ഒ\s*ടി\s*പി",
    r"പാസ്\s*വേർഡ്",
    r"പിൻ\s*(നമ്പർ)?",
    r"സി\s*വി\s*വി",
    r"വെരിഫിക്കേഷൻ കോഡ്",
    r"ഒടിപി\s*(ഒന്ന്\s*)?(പറഞ്ഞു|തരൂ|അയക്കൂ|ഷെയർ)",
    r"പാസ്‌വേഡ്\s*(പറയൂ|തരൂ)",
    r"ആധാർ\s*(നമ്പർ)?",

    # Manglish / Mixed
    r"\botp (paranju|parayoo|tharu|tharumo|ayakk|share cheyy|venam|send cheyy)\b",
    r"\b(pin|password|cvv) (paray|tharu|venam|share)\b",
    r"\bverification code (paray|tharu|venam)\b",
    r"\bente phone-il vanna otp\b",
]

# 2. Account Threat / Suspension / KYC Expiry (Urgency + Threat)
ACCOUNT_THREAT_PATTERNS = [
    # English
    r"\baccount (has been|will be|is) (blocked|suspended|deactivated|frozen|terminated|locked)\b",
    r"\bbank account blocked\b",
    r"\bkyc (is )?(expired|pending|suspended|incomplete)\b",
    r"\bupdate (your )?kyc\b",
    r"\bdebit card (blocked|expired)\b",
    r"\bsim card (will be )?deactivated\b",
    r"\bunauthorized transaction\b",
    r"\bsuspicious activity (on|in) your account\b",
    r"\bfailure to (comply|verify)\b",

    # Malayalam Script
    r"അക്കൗണ്ട്\s*(ബ്ലോക്ക്|മരവിപ്പിച്ചു|റദ്ദാക്കി)",
    r"ബാങ്ക്\s*അക്കൗണ്ട്",
    r"കെ\s*വൈ\s*സി\s*(കാലഹരണപ്പെട്ടു|അപ്ഡേറ്റ്)",
    r"സിം\s*കാർഡ്\s*റദ്ദാക്കും",
    r"അക്കൗണ്ട്\s*പൂട്ടും",

    # Manglish / Mixed
    r"\baccount (block|suspended|freeze) (aayi|aayittundu|aakum|cheyyum)\b",
    r"\bkyc (update|complete) (cheyyanam|cheyyu|cheythillel)\b",
    r"\bbank account block\b",
    r"\bsim (deactivate|block) aakum\b",
    r"\bningalude account block\b",
]

# 3. Financial / Payment Demands
FINANCIAL_PATTERNS = [
    # English
    r"\bsend (the )?money\b",
    r"\btransfer (the |a )?(fine |total )?(amount|funds|money|cash)\b",
    r"\btransfer\b.*\b(upi|gpay|bank|rupees|account)\b",
    r"\bpay (immediately|now|the fee|fine|penalty)\b",
    r"\b(via |through )?(upi|gpay|phonepe|paytm)\b",
    r"\bupi (transfer|id|payment)\b",
    r"\bgpay\b",
    r"\bphonepe\b",
    r"\bpaytm\b",
    r"\bwire transfer\b",
    r"\brefund (process|amount)\b",
    r"\bprocessing fee\b",
    r"\bdeposit (amount|money)\b",

    # Malayalam Script
    r"പണം\s*(അയക്കൂ|ട്രാൻസ്ഫർ|തരണം|നൽകണം)",
    r"തുക\s*(അടയ്ക്കണം|നൽകണം)",
    r"പൈസ\s*(അയക്കൂ|തരണം|ഇടണം)",
    r"ഫീസ്\s*അടയ്ക്കണം",
    r"റീഫണ്ട്\s*ലഭിക്കാൻ",

    # Manglish / Mixed
    r"\b(paisa|panam|amount) (ayakk|transfer cheyy|tharu|adakk)\b",
    r"\b(gpay|phonepe|paytm|upi) (vazhi|cheyy|ayakk)\b",
    r"\bfee adakkanam\b",
    r"\brefund kittan\b",
]

# 4. Urgency & Coercion / Artificial Time Pressure
URGENCY_PATTERNS = [
    # English
    r"\bimmediately\b",
    r"\burgent(ly)?\b",
    r"\bwithin (5|10|15|30|60) minutes\b",
    r"\bact now\b",
    r"\bfinal warning\b",
    r"\blast chance\b",
    r"\bright now\b",
    r"\bdo not disconnect\b",
    r"\bdo not tell (anyone|family|police)\b",
    r"\bkeep (this|the call) confidential\b",

    # Malayalam Script
    r"ഉടൻ\s*തന്നെ",
    r"ഇപ്പോൾ\s*തന്നെ",
    r"അടിയന്തരമായി",
    r"അവസാന\s*(അവസരം|മുന്നറിയിപ്പ്)",
    r"ആരോടും\s*പറയരുത്",
    r"കോൾ\s*കട്ട്\s*ചെയ്യരുത്",

    # Manglish / Mixed
    r"\bippol thanne\b",
    r"\budan thanne\b",
    r"\burgent aayi\b",
    r"\bsamayam illa\b",
    r"\barodum parayaruthu\b",
    r"\bcall cut cheyyaruthu\b",
]

# 5. Authority & Entity Impersonation
IMPERSONATION_PATTERNS = [
    # English
    r"\bpolice( officer)?\b",
    r"\bcyber (crime|police|cell)\b",
    r"\bcbi( officer)?\b",
    r"\brbi( official)?\b",
    r"\bbank (manager|official|support|officer|executive)\b",
    r"\bcustoms (officer|department|parcel)\b",
    r"\bfedex (officer|courier|parcel)\b",
    r"\bcourt (warrant|summons|order)\b",
    r"\barrest (warrant)?\b",
    r"\btax (department|evasion)\b",
    r"\bcustomer (care|support|service)\b",
    r"\bcalling from (sbi|hdfc|icici|kavach|reserve bank|head office)\b",

    # Malayalam Script
    r"പോലീസ്\s*(ഉദ്യോഗസ്ഥൻ|സ്റ്റേഷൻ)?",
    r"സൈബർ\s*ക്രൈം",
    r"ബാങ്ക്\s*മാനേജർ",
    r"കസ്റ്റംസ്\s*(ഓഫീസർ)?",
    r"കോടതി\s*(ഉത്തരവ്)?",
    r"അറസ്റ്റ്\s*ചെയ്യും",
    r"കസ്റ്റമർ\s*കെയർ",

    # Manglish / Mixed
    r"\bbankil ninnanu vilikkunnathe\b",
    r"\bhead office-il ninnu\b",
    r"\bpolice (officer|stationil ninnu)\b",
    r"\bcyber cell-il ninnu\b",
    r"\bcase edukkum\b",
    r"\barrest cheyyum\b",
]

# 6. Remote Access & Malicious Links
REMOTE_ACCESS_PATTERNS = [
    # English
    r"\banydesk\b",
    r"\bteamviewer\b",
    r"\bquicksupport\b",
    r"\brustdesk\b",
    r"\bdownload (the )?(app|application|software|apk)\b",
    r"\binstall (the )?(app|support tool|apk)\b",
    r"\bgive (me )?access\b",
    r"\bscreen share\b",
    r"\bclick (the |on )?link\b",

    # Malayalam Script
    r"ആപ്പ്\s*ഡൗൺലോഡ്\s*ചെയ്യുക",
    r"ഇൻസ്റ്റാൾ\s*ചെയ്യുക",
    r"ലിങ്കിൽ\s*ക്ലിക്ക്\s*ചെയ്യുക",
    r"സ്ക്രീൻ\s*ഷെയർ",

    # Manglish / Mixed
    r"\bapp (download|install) (cheyyu|cheyyanam)\b",
    r"\blink-il click cheyyu\b",
    r"\bscreen share cheyyu\b",
]

# 7. Prize / Lottery / Reward Schemes
PRIZE_PATTERNS = [
    # English
    r"\blottery( prize)?\b",
    r"\bcongratulations,?\s+you (have )?won\b",
    r"\byou have won\b",
    r"\bcash prize\b",
    r"\blakhs? of rupees\b",
    r"\bclaim (your )?(reward|prize|cash)\b",
    r"\bgift voucher\b",

    # Malayalam Script
    r"സമ്മാനം\s*(അടിച്ചു|ലഭിച്ചു)",
    r"ലോട്ടറി\s*(അടിച്ചു|തുക)",
    r"നിങ്ങൾക്ക്\s*ലഭിച്ചിരിക്കുന്നു",

    # Manglish / Mixed
    r"\b(prize|lottery) (adichu|kittiyittundu)\b",
    r"\bningal jayichu\b",
]

# Safe Conversational Greetings / Whitelist for calibration
SAFE_GREETINGS = [
    r"^\s*(hello|hi|good morning|good afternoon|good evening|how are you|namaskaram|enthokkeyundu vishesham|sukhamano)\s*$",
    r"^\s*(bye|see you later|thank you|thanks|valare nanni|pinne kaanam)\s*$",
]


class LiveVoiceRiskService:
    """
    Intelligent Multi-lingual Voice Scam & Vishing Detection Service.
    Analyzes live transcript chunks with explainable risk scoring.
    """

    @classmethod
    def analyze_transcript(
        cls,
        text: str,
        speaker: Optional[str] = None,
        language: Optional[str] = None,
        context_history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Analyzes a single transcript segment (or concatenated rolling window).

        Args:
            text: Spoken utterance text
            speaker: Speaker identifier ('Participant 1', 'Caller', etc.)
            language: Optional language hint ('en', 'ml', 'mixed')
            context_history: Optional list of recent turns for multi-turn correlation

        Returns:
            {
                "risk_level": "SAFE" | "SUSPICIOUS" | "HIGH RISK",
                "risk_score": int (0 - 100),
                "detected_indicators": List[str],
                "reasons": List[str],
                "recommended_action": str,
                "summary": str,
                "detected_language": str
            }
        """
        if not text or not text.strip():
            return {
                "risk_level": "SAFE",
                "risk_score": 0,
                "detected_indicators": [],
                "reasons": ["No speech or empty transcript chunk."],
                "recommended_action": "Listening for active voice conversation...",
                "summary": "Audio stream clear.",
                "detected_language": language or "en",
            }

        content = text.strip()

        # Import language detector from STT service
        from app.services.live_voice_stt_service import detect_transcript_language
        detected_lang = detect_transcript_language(content, hint_language=language)

        # Quick check for innocuous short greeting
        for safe_p in SAFE_GREETINGS:
            if re.match(safe_p, content, re.IGNORECASE):
                return {
                    "risk_level": "SAFE",
                    "risk_score": 0,
                    "detected_indicators": [],
                    "reasons": ["Normal conversational greeting detected."],
                    "recommended_action": "Standard communication. Always maintain general digital safety hygiene.",
                    "summary": "Conversational greeting - No risk detected.",
                    "detected_language": detected_lang,
                }

        # Check also rolling context if provided
        combined_text = content
        if context_history and isinstance(context_history, list):
            recent_texts = [turn.get("text", "") for turn in context_history[-4:] if turn.get("text")]
            combined_text = " ".join(recent_texts + [content])

        detected_indicators = []
        reasons = []
        base_score = 0

        # 1. Credential & OTP Harvesting Attempt (Weight: 40-50)
        cred_matches = [p for p in CREDENTIAL_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if cred_matches:
            base_score += 45
            detected_indicators.append("OTP / Credential Harvesting Request")
            reasons.append("Speaker explicitly requests confidential verification codes, OTP, PIN, or passwords.")

        # 2. Account Threat / Suspension Alert (Weight: 25-35)
        threat_matches = [p for p in ACCOUNT_THREAT_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if threat_matches:
            base_score += 30
            detected_indicators.append("Account Suspension / KYC Threat")
            reasons.append("Speaker claims your bank account is blocked or KYC is expired to trigger panic.")

        # 3. Financial & Payment Demands (Weight: 25-35)
        fin_matches = [p for p in FINANCIAL_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if fin_matches:
            base_score += 30
            detected_indicators.append("Urgent Payment / Money Transfer Request")
            reasons.append("Demands immediate monetary transfer, UPI payment, or processing fees.")

        # 4. Authority / Police / Bank Impersonation (Weight: 25-35)
        imp_matches = [p for p in IMPERSONATION_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if imp_matches:
            base_score += 30
            detected_indicators.append("Authority / Bank Impersonation")
            reasons.append("Speaker claims authority from bank management, police, cyber crime, or customs.")

        # 5. Urgency & Coercion Pressure (Weight: 15-25)
        urg_matches = [p for p in URGENCY_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if urg_matches:
            base_score += 20
            detected_indicators.append("Artificial Urgency & Secrecy Coercion")
            reasons.append("Pressures user to act immediately or demands secrecy to bypass rational verification.")

        # 6. Remote Access / Suspicious Link (Weight: 30-40)
        remote_matches = [p for p in REMOTE_ACCESS_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if remote_matches:
            base_score += 35
            detected_indicators.append("Remote Access Software / Malicious App")
            reasons.append("Instructs caller to install remote control applications (AnyDesk/TeamViewer) or click links.")

        # 7. Prize / Lottery / Reward Trap (Weight: 20-30)
        prize_matches = [p for p in PRIZE_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if prize_matches:
            base_score += 25
            detected_indicators.append("Unverified Lottery / Reward Trap")
            reasons.append("Claims fraudulent lottery winnings or cash rewards to lure user.")

        # -------------------------------------------------------------------
        # DYNAMIC COMPOUNDING RISK FORMULA
        # -------------------------------------------------------------------
        # Multi-signal correlation: Vishing scams strongly correlate when
        # threat + credential harvesting or threat + payment occur simultaneously.
        indicator_count = len(detected_indicators)

        if indicator_count >= 3:
            # Strong multi-vector attack (e.g. Bank Impersonation + Account Blocked + OTP Request)
            calculated_score = max(80, base_score + 15)
        elif indicator_count == 2:
            # Pair correlation
            if "OTP / Credential Harvesting Request" in detected_indicators:
                calculated_score = max(70, base_score + 10)
            else:
                calculated_score = max(50, base_score + 5)
        elif indicator_count == 1:
            if "OTP / Credential Harvesting Request" in detected_indicators:
                calculated_score = 65  # Single OTP request is inherently high risk
            elif "Account Suspension / KYC Threat" in detected_indicators:
                calculated_score = 45  # Suspicious until verified
            elif "Urgent Payment / Money Transfer Request" in detected_indicators:
                calculated_score = 45
            elif "Authority / Bank Impersonation" in detected_indicators:
                calculated_score = 40
            elif "Remote Access Software / Malicious App" in detected_indicators:
                calculated_score = 60
            else:
                calculated_score = min(35, base_score)
        else:
            calculated_score = 0

        # Bound score strictly to 0-100
        risk_score = max(0, min(100, calculated_score))

        # -------------------------------------------------------------------
        # RISK CATEGORIZATION (0-29: SAFE, 30-59: SUSPICIOUS, 60-100: HIGH RISK)
        # -------------------------------------------------------------------
        if risk_score >= 60:
            risk_level = "HIGH RISK"
            summary = "🔴 Critical vishing scam indicators detected in active voice stream."
            recommended_action = "DO NOT share OTP, PIN, password, or banking credentials. Disconnect immediately."
        elif risk_score >= 30:
            risk_level = "SUSPICIOUS"
            summary = "🟡 Suspicious conversational patterns detected. Potential social engineering attempt."
            recommended_action = "Exercise caution. Do not make hasty payments or share personal details."
        else:
            risk_level = "SAFE"
            summary = "🟢 Normal voice conversation. No scam patterns detected."
            recommended_action = "Standard conversation. General safety practices apply."
            if not reasons:
                reasons.append("No urgency, credential solicitation, or fraudulent claims identified.")

        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "detected_indicators": detected_indicators,
            "reasons": reasons,
            "recommended_action": recommended_action,
            "summary": summary,
            "detected_language": detected_lang,
        }


def analyze_voice_transcript(
    text: str,
    speaker: Optional[str] = None,
    language: Optional[str] = None,
    context_history: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    return LiveVoiceRiskService.analyze_transcript(
        text=text,
        speaker=speaker,
        language=language,
        context_history=context_history
    )
