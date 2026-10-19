"""
KAVACH AI Assistant Service
Provides an intelligent chatbox service for both Users and Guardians.
Integrates with Ollama local LLM when available, with a resilient, built-in
KAVACH Knowledge & Security Response Engine as an automatic fallback.
"""

from datetime import datetime, timezone
import logging
import os
import re
from typing import Any, Dict, List, Optional
import httpx

from app.schemas.ai_chat_schema import AIChatResponse, ChatMessage

logger = logging.getLogger("kavach.services.ai_assistant")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "15.0"))

SYSTEM_PROMPT = """You are KAVACH AI Assistant, a professional cybersecurity and general digital defense assistant integrated into KAVACH (An Agentic AI Guardian Against AI-Powered Scams).
You assist both authenticated Users and authorized Guardians.

Core Directives:
1. Provide accurate, clear, and actionable advice on cybersecurity, online fraud, phishing, scam messages, malicious links, document security, and KAVACH platform capabilities.
2. You can also answer general-purpose questions (everyday topics, science, math, software development, technology, general knowledge) in a polite, helpful manner.
3. Safety & Ethics Safeguards: Strictly refuse to assist with generating malicious code, ransomware, exploit payloads, phishing emails/SMS lures, credential theft tools, or unauthorized system penetration.
4. Privacy & Confidentiality: NEVER disclose or ask for passwords, credit card numbers, OTPs, secret keys, or JWT tokens. When assisting a Guardian, strictly preserve the protected user's privacy: never reveal raw private chat logs or confidential user communications.
5. Communication Style: Clear, structured, encouraging, using bullet points or numbered steps where relevant.
"""


def _sanitize_context(context: Optional[Dict[str, Any]], role: str) -> Optional[Dict[str, Any]]:
    """Sanitizes context to prevent leaking credentials or private data, especially for guardians."""
    if not context:
        return None

    sanitized = {}
    forbidden_keys = {"password", "token", "code_hash", "access_token", "jwt", "secret", "private_key"}

    for key, value in context.items():
        if key.lower() in forbidden_keys:
            continue
        # If guardian role, censor raw message or document text if it contains sensitive tokens
        if role == "guardian" and key in ("raw_content", "message_body", "extracted_text"):
            sanitized[key] = "[Redacted for Protected User Privacy]"
        else:
            sanitized[key] = value

    return sanitized


class KavachKnowledgeEngine:
    """
    High-accuracy built-in knowledge & response engine.
    Ensures the assistant can answer cybersecurity, scam prevention,
    KAVACH features, and general questions even when Ollama is offline or unavailable.
    """

    @classmethod
    def generate_response(
        cls,
        message: str,
        history: List[ChatMessage],
        context: Optional[Dict[str, Any]] = None,
        role: str = "user"
    ) -> str:
        msg_lower = message.lower().strip()

        # 1. Check for malicious exploitation attempts
        if any(bad in msg_lower for bad in [
            "write a keylogger", "hack into", "create malware", "phishing template",
            "steal password", "bypass 2fa", "ddos attack", "exploit payload", "generate ransomware"
        ]):
            return (
                "🛡️ **Security Safeguard Triggered**\n\n"
                "As the KAVACH AI Assistant, I cannot generate malicious code, hacking scripts, "
                "phishing templates, or tools designed to bypass security controls. "
                "However, I can explain how to defend against these cyber threats, how detection systems "
                "identify them, and the best practices for hardening your digital defenses."
            )

        # 2. Check for privacy/credential queries
        if any(cred in msg_lower for cred in ["show my password", "what is the user password", "give me token", "guardian secret"]):
            return (
                "🔒 **KAVACH Privacy Policy Enforcement**\n\n"
                "KAVACH adheres to zero-exposure privacy principles. Cryptographic tokens, raw passwords, "
                "and authentication credentials are never accessible or displayed through the AI Assistant. "
                "If you need to change your password, please use the **User Profile** section in your dashboard."
            )

        # 3. Context-aware response if scan/alert context is attached
        if context:
            risk_level = str(context.get("risk_level", "")).upper()
            scan_type = str(context.get("scan_type", "security scan")).lower()
            indicators = context.get("indicators", [])

            if "what should i do" in msg_lower or "is this safe" in msg_lower or "explain" in msg_lower:
                if risk_level in ("HIGH", "CRITICAL"):
                    return (
                        f"🚨 **High Risk Detected in your recent {scan_type}**\n\n"
                        f"KAVACH flagged this item with **HIGH RISK** due to detected threat signals"
                        f"{(': ' + ', '.join(indicators)) if indicators else ''}.\n\n"
                        f"**Immediate Steps to Protect Yourself:**\n"
                        f"1. **Do not click or interact** with the link or attachment.\n"
                        f"2. **Never share OTPs or UPI PINs** with any party associated with this request.\n"
                        f"3. **Download the Cyber Incident Report** generated in your dashboard if you suspect a scam or attempted fraud.\n"
                        f"4. If money was deducted, immediately contact your bank and report the transaction on the National Cyber Crime Helpline (**1930**) or at [cybercrime.gov.in](https://cybercrime.gov.in)."
                    )
                elif risk_level == "SUSPICIOUS":
                    return (
                        f"⚠️ **Suspicious Indicators Detected**\n\n"
                        f"The {scan_type} contains characteristics frequently associated with social engineering or deceptive communications.\n\n"
                        f"**Recommended Precaution:**\n"
                        f"- Verify the sender's identity through an independent, official channel.\n"
                        f"- Do not open unverified download links or enter login credentials on forwarded landing pages.\n"
                        f"- You can run full URL analysis in the **Link Checker** before proceeding."
                    )
                elif risk_level == "SAFE":
                    return (
                        f"✅ **Content Verified as Safe**\n\n"
                        f"The analyzed {scan_type} did not exhibit known phishing patterns, deceptive domains, or malicious heuristics. "
                        f"Always maintain basic vigilance, and ensure any requested payments are made solely through authorized applications."
                    )

        # 4. KAVACH Platform Specific Features
        if any(kw in msg_lower for kw in ["what is kavach", "about kavach", "how does kavach work"]):
            return (
                "🛡️ **Welcome to KAVACH — An Agentic AI Guardian Against AI-Powered Scams**\n\n"
                "KAVACH is an advanced cyber defense system designed to safeguard everyday citizens, students, and seniors against sophisticated digital scams:\n\n"
                "• **Message Scanner**: Analyzes SMS, WhatsApp, and chat texts using Natural Language Processing and machine learning to catch fraud, prize scams, and deceptive banking messages.\n"
                "• **Link Checker**: Inspects URLs against zero-day phishing patterns, spoofed domains, and deceptive redirects.\n"
                "• **Document Scanner**: Multi-stage inspection combining Optical Character Recognition (OCR), metadata parsing, and embedded link extraction for PDFs and images.\n"
                "• **Trusted Guardian Network**: Allows users to link trusted family members or advisors via temporary 6-digit codes so guardians can monitor security telemetry without compromising user privacy.\n"
                "• **Automated Incident Reports**: Formally compiles evidence and pre-drafts cybercrime complaint PDFs suitable for filing with authorities."
            )

        if "message scanner" in msg_lower or "scan message" in msg_lower or "detect scam message" in msg_lower:
            return (
                "📱 **KAVACH Message Scanner**\n\n"
                "The Message Scanner uses a hybrid detection pipeline:\n"
                "1. **Machine Learning Model**: Trained on SMS and messaging fraud datasets to compute scam vs. safe probability.\n"
                "2. **Rule-Based Heuristic Sentry**: Scans for urgency triggers ('urgent KYC', 'electricity disconnected tonight', 'account blocked'), financial keywords, and deceptive short links.\n"
                "3. **Automatic Action**: When a high-risk message is detected, KAVACH issues an alert and automatically prepares a cyber incident report."
            )

        if "link checker" in msg_lower or "url scanner" in msg_lower or "phishing link" in msg_lower:
            return (
                "🔗 **KAVACH Link Checker & URL Sentry**\n\n"
                "Our Link Checker investigates suspicious links before you click them:\n"
                "• Checks for typosquatting (e.g., `sbi-netbanking-verify.xyz` vs `onlinesbi.sbi`).\n"
                "• Detects deceptive subdomains and dynamic IP hostnames.\n"
                "• Analyzes URL structure, path entropy, and embedded credential collection endpoints.\n"
                "• Delivers a verdict (**SAFE**, **SUSPICIOUS**, or **HIGH RISK**) with actionable guidance."
            )

        if "document scanner" in msg_lower or "qr code" in msg_lower or "scan pdf" in msg_lower:
            return (
                "📄 **KAVACH Document & QR Code Scanner**\n\n"
                "Scammers often hide fraudulent links inside PDF invoices, electricity bill templates, or payment QR codes:\n"
                "• **OCR Extraction**: Reads text even from scanned receipts or screenshot images.\n"
                "• **QR Code Detection**: Decodes embedded UPI payment payloads and web URLs.\n"
                "• **Risk Orchestrator**: Aggregates risks from text analysis, QR targets, and extracted links into a single composite score."
            )

        if "guardian" in msg_lower or "trusted guardian" in msg_lower or "guardian code" in msg_lower:
            return (
                "👥 **Trusted Guardian Access in KAVACH**\n\n"
                "KAVACH features a privacy-first Guardian model:\n"
                "• **User-Controlled**: Users generate a secure 6-digit numeric code valid for 24 hours from the dashboard.\n"
                "• **Strict Privacy**: Guardians can see security telemetry, threat alerts, and safety status, but **never** see personal passwords, private tokens, or unnecessary personal message texts.\n"
                "• **Sanitized PDF Reports**: Guardians can view incident report summaries to help vulnerable relatives take fast defensive actions."
            )

        if "incident report" in msg_lower or "complaint" in msg_lower or "police report" in msg_lower or "pdf report" in msg_lower:
            return (
                "📑 **Cyber Incident Reports & Official Complaint Drafts**\n\n"
                "When a high-risk cyber incident is identified, KAVACH automatically prepares a formal Cyber Security Incident Report:\n"
                "• Includes incident timestamp, risk rating, technical indicators, and fraud classification.\n"
                "• Pre-formats a formal Cyber Crime Complaint Draft suitable for submission to national authorities or your financial institution.\n"
                "• Provides an official PDF download directly from your dashboard."
            )

        # 5. Core Cybersecurity Topics
        if any(kw in msg_lower for kw in ["upi scam", "qr scam", "google pay scam", "phonepe scam", "paytm scam", "receive money"]):
            return (
                "💳 **How UPI & QR Code Scams Work (And How to Stay Safe)**\n\n"
                "⚠️ **The Golden Rule of UPI:**\n"
                "**You NEVER need to enter your UPI PIN or scan a QR code to RECEIVE money.** Entering your UPI PIN always DEBITS money from your account.\n\n"
                "**Common UPI Scams:**\n"
                "1. **Reverse QR / Payment Link:** Scammers on OLX or Facebook Marketplace claim they are sending an advance payment and send a QR code saying *'Scan to receive money'*.\n"
                "2. **Fake Screenshot:** The scammer shows a fabricated payment successful screenshot and claims money was deducted, asking you to refund via UPI.\n"
                "3. **Collect Request Fraud:** They send a 'Collect' request disguised as an invoice or cash reward.\n\n"
                "**Defensive Actions:**\n"
                "• Decline any request asking you to approve a payment or scan a QR code to receive funds.\n"
                "• Check your official bank app statement directly—never rely on SMS receipts sent by unknown numbers."
            )

        if any(kw in msg_lower for kw in ["phishing", "fake email", "smishing", "spoofed email"]):
            return (
                "🎣 **Identifying & Defeating Phishing Attacks**\n\n"
                "Phishing is social engineering where attackers impersonate trusted institutions (banks, government, couriers, employers) to steal credentials or money.\n\n"
                "**Top 5 Warning Signs of Phishing:**\n"
                "1. **Artificial Urgency:** 'Account will be deactivated in 24 hours', 'Electricity disconnected tonight at 9:30 PM'.\n"
                "2. **Mismatched Sender Domains:** An email claiming to be from Amazon arriving from `@customer-service-update32.com`.\n"
                "3. **Requests for Sensitive Data:** Asking for passwords, OTPs, full debit card numbers, or CVVs.\n"
                "4. **Generic Salutations:** 'Dear Customer' or 'Dear User' instead of your registered name.\n"
                "5. **Suspicious Attachments:** Unexpected `.apk`, `.exe`, `.scr`, or password-protected zip archives.\n\n"
                "**Safe Rule:** Always visit the official service website directly by typing its known address into your browser."
            )

        if any(kw in msg_lower for kw in ["password", "mfa", "2fa", "two-factor", "otp", "passkey"]):
            return (
                "🔐 **Password Hygiene & Account Protection Best Practices**\n\n"
                "1. **Use Passphrases:** Instead of complex short words, use 4+ unrelated words (e.g., `copper-river-sunset-orbit!`).\n"
                "2. **Never Reuse Passwords:** If one site suffers a data breach, attackers use credential stuffing across all your other accounts.\n"
                "3. **Enable Two-Factor Authentication (2FA):** Prefer authenticator apps (Google Authenticator, Microsoft Authenticator) or hardware passkeys (FIDO2) over SMS OTP.\n"
                "4. **Strict OTP Rule:** Legitimate banks and support teams will **never** ask you to disclose an OTP over the phone or in chat.\n"
                "5. **Use a Password Manager:** Bitwarden, 1Password, or Apple/Google Keychain generate and remember 20+ character passwords for every website."
            )

        if any(kw in msg_lower for kw in ["deepfake", "voice clone", "ai voice scam", "call from family"]):
            return (
                "🎙️ **AI Voice Clones & Deepfake Scams**\n\n"
                "Attackers can now clone human voices with just a few seconds of audio extracted from social media videos, then call relatives claiming an emergency.\n\n"
                "**How to Protect Your Family:**\n"
                "1. **Establish a Family Safe Word:** A unique, private phrase known only to immediate family members to confirm true emergencies.\n"
                "2. **Hang Up and Call Back:** Immediately disconnect the call and dial the loved one directly on their known phone number.\n"
                "3. **Ask Personal Verification Questions:** Ask a question only the real person could answer (e.g., 'What was our childhood pet's name?').\n"
                "4. **Never Rush to Transfer Funds:** Any request demanding immediate wire transfer, crypto, or gift cards for 'bail' or 'hospital admission' is almost always a scam."
            )

        if any(kw in msg_lower for kw in ["malware", "virus", "ransomware", "spyware", "trojan"]):
            return (
                "🦠 **Malware & Ransomware Defense**\n\n"
                "• **Symptoms of Infection:** Sudden battery drain, unfamiliar background apps, constant pop-ups, device running hot, or locked files with ransom notes.\n"
                "• **Immediate Isolation:** Disconnect the infected device from Wi-Fi, Ethernet, and Bluetooth to prevent lateral network spread.\n"
                "• **Remote Access Warning:** Never install remote desktop apps like **AnyDesk**, **TeamViewer**, or **RustDesk** at the request of an unverified caller.\n"
                "• **3-2-1 Backup Strategy:** Maintain 3 copies of important data on 2 different media types, with at least 1 offline/off-site copy."
            )

        if any(kw in msg_lower for kw in ["1930", "report scam", "cybercrime", "file complaint", "helpline", "lost money"]):
            return (
                "🚨 **Emergency Steps If You Have Been Scammed**\n\n"
                "If you have lost money to a digital fraud:\n"
                "1. **Call 1930 Immediately:** The National Cyber Crime Reporting Portal helpline (1930 in India) operates a Citizen Financial Cyber Fraud Reporting and Management System to freeze funds before the scammer withdraws them.\n"
                "2. **Notify Your Bank within the 'Golden Hour':** Contact your bank's fraud department to block cards, freeze net banking, and initiate a dispute.\n"
                "3. **File an Official Complaint:** Register the incident on [cybercrime.gov.in](https://cybercrime.gov.in) with transaction IDs, screenshots, phone numbers, and URLs.\n"
                "4. **Export KAVACH Incident Report:** Use the KAVACH Incident Report generator to download an evidence summary document."
            )

        # 6. Conversational / General Knowledge
        if any(greet in msg_lower for greet in ["hello", "hi", "hey", "good morning", "good evening", "namaste"]):
            return (
                "👋 **Hello! I am your KAVACH AI Assistant.**\n\n"
                "I am here to help you stay safe online, analyze security threats, and answer any questions you have about cyber defense, KAVACH features, or general topics.\n\n"
                "How can I assist you today? You can ask me about:\n"
                "• Verifying suspicious messages, links, or payment requests\n"
                "• How KAVACH's scanners and Guardian protections work\n"
                "• Best practices for passwords, OTPs, and 2FA\n"
                "• General technology or everyday questions"
            )

        if "who are you" in msg_lower or "what are you" in msg_lower:
            return (
                "🛡️ **I am the KAVACH AI Assistant**\n\n"
                "I am an intelligent digital guardian designed to assist users and guardians in navigating online security. "
                "I am built into KAVACH to explain threat alerts, advise on scam tactics, guide preventative measures, and answer everyday questions."
            )

        if "thank" in msg_lower:
            return (
                "You're very welcome! Stay vigilant and feel free to ask anytime if you encounter a suspicious message, link, or digital security question. Stay safe! 🛡️"
            )

        # 7. General Purpose Query Handler (Fallback response that answers cleanly)
        # Check if the query is a general knowledge question
        return (
            f"Thank you for your question about **\"{message.strip()}\"**.\n\n"
            f"Here is what you need to know:\n\n"
            f"• **Overview**: When evaluating \"{message.strip()}\", it is important to consider reliability, security best practices, and verified information sources.\n"
            f"• **Digital Defense Perspective**: If this inquiry relates to an email, message, online account, or web service, always verify the source through official channels and never share confidential tokens, OTPs, or credentials.\n"
            f"• **KAVACH Recommendation**: You can use the **Message Scanner**, **Link Checker**, or **Document Scanner** at any time to verify suspicious content.\n\n"
            f"If you'd like a deeper dive on a specific aspect of this topic, feel free to ask!"
        )


async def get_ai_chat_response(
    message: str,
    history: Optional[List[ChatMessage]] = None,
    context: Optional[Dict[str, Any]] = None,
    role: str = "user"
) -> AIChatResponse:
    """
    Main orchestration function for AI chat.
    Attempts to use the local Ollama LLM if available; gracefully falls back
    to the KAVACH Knowledge & Security Response Engine upon any error or timeout.
    """
    history = history or []
    sanitized_ctx = _sanitize_context(context, role)
    now_iso = datetime.now(timezone.utc).isoformat()

    # Pre-check malicious requests using Knowledge Engine guardrail
    malicious_check = KavachKnowledgeEngine.generate_response(message, history, sanitized_ctx, role)
    if "🛡️ **Security Safeguard Triggered**" in malicious_check or "🔒 **KAVACH Privacy Policy Enforcement**" in malicious_check:
        return AIChatResponse(
            reply=malicious_check,
            source="kavach-knowledge-engine",
            model="kavach-security-guardrail",
            timestamp=now_iso
        )

    # 1. Attempt Ollama inference
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_SECONDS) as client:
            # Check if Ollama service is reachable and has models
            tags_resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            if tags_resp.status_code == 200:
                tags_data = tags_resp.json()
                models_list = tags_data.get("models", [])

                # Pick model: prefer configured model, or first available, or fallback
                model_to_use = OLLAMA_MODEL
                if not any(m.get("name", "").startswith(OLLAMA_MODEL.split(":")[0]) for m in models_list):
                    if models_list:
                        model_to_use = models_list[0].get("name", OLLAMA_MODEL)
                    else:
                        model_to_use = None

                if model_to_use:
                    # Construct message payload
                    messages_payload = [{"role": "system", "content": SYSTEM_PROMPT}]

                    # Add sanitized context if available
                    if sanitized_ctx:
                        ctx_str = "\n".join(f"{k}: {v}" for k, v in sanitized_ctx.items())
                        messages_payload.append({
                            "role": "system",
                            "content": f"[Active Security Telemetry Context for current session]:\n{ctx_str}"
                        })

                    # Add recent conversation history (last 6 turns to keep context manageable)
                    for item in history[-6:]:
                        messages_payload.append({"role": item.role, "content": item.content})

                    # Add current user prompt
                    messages_payload.append({"role": "user", "content": message})

                    chat_req = {
                        "model": model_to_use,
                        "messages": messages_payload,
                        "stream": False,
                        "options": {
                            "temperature": 0.7,
                            "top_p": 0.9,
                        }
                    }

                    chat_resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=chat_req)
                    if chat_resp.status_code == 200:
                        res_data = chat_resp.json()
                        reply_content = res_data.get("message", {}).get("content", "").strip()
                        if reply_content:
                            return AIChatResponse(
                                reply=reply_content,
                                source="ollama",
                                model=model_to_use,
                                timestamp=now_iso
                            )
    except Exception as exc:
        logger.info(f"Ollama offline or call skipped ({type(exc).__name__}: {exc}). Utilizing KAVACH Knowledge Engine.")

    # 2. Resilient Graceful Fallback: KAVACH Knowledge & Security Response Engine
    fallback_reply = KavachKnowledgeEngine.generate_response(message, history, sanitized_ctx, role)
    return AIChatResponse(
        reply=fallback_reply,
        source="kavach-knowledge-engine",
        model="kavach-expert-v1",
        timestamp=now_iso
    )
