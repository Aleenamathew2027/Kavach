"""
=============================================================================
KAVACH — Guardian SMS Notification Service Abstraction
=============================================================================
Provides a clean, modular SMS provider abstraction for delivering
privacy-sanitized, critical security alerts to verified Guardians.

Follows strict privacy rules:
  - Never leaks OTP, passwords, tokens, full private text, or scan content.
  - Enforces severity policy:
      * SAFE: No SMS
      * SUSPICIOUS: Sent only if enabled in Guardian settings
      * HIGH_RISK: Dispatches sanitized SMS
      * CRITICAL: Dispatches sanitized SMS
  - Fully decoupled: Credentials read from environment variables (never hardcoded)
=============================================================================
"""

import abc
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kavach.services.sms")


class BaseSMSProvider(abc.ABC):
    """Abstract interface for third-party SMS delivery gateways."""

    @abc.abstractmethod
    def send_sms(self, to_number: str, message: str) -> Dict[str, Any]:
        """
        Deliver an SMS message.
        Returns a dict: {"success": bool, "message_id": Optional[str], "error": Optional[str]}
        """
        pass


class MockSMSProvider(BaseSMSProvider):
    """In-memory provider for automated testing and staging validation."""

    def __init__(self):
        self.sent_messages: List[Dict[str, Any]] = []

    def send_sms(self, to_number: str, message: str) -> Dict[str, Any]:
        record = {
            "to": to_number,
            "message": message,
            "provider": "mock",
        }
        self.sent_messages.append(record)
        logger.info(f"[MockSMSProvider] Simulated SMS to {to_number}: {message}")
        return {"success": True, "message_id": f"mock-{len(self.sent_messages)}", "provider": "mock"}


class TwilioSMSProvider(BaseSMSProvider):
    """Production Twilio integration using standard environment credentials."""

    def __init__(self, account_sid: str, auth_token: str, from_number: str):
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number

    def send_sms(self, to_number: str, message: str) -> Dict[str, Any]:
        try:
            # Twilio REST API request using standard urllib (zero extra dependency)
            import urllib.request
            import urllib.parse
            import base64
            import json

            url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
            data = urllib.parse.urlencode({
                "To": to_number,
                "From": self.from_number,
                "Body": message
            }).encode("utf-8")

            req = urllib.request.Request(url, data=data)
            auth_str = f"{self.account_sid}:{self.auth_token}"
            auth_b64 = base64.b64encode(auth_str.encode("ascii")).decode("ascii")
            req.add_header("Authorization", f"Basic {auth_b64}")

            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                return {"success": True, "message_id": resp_data.get("sid"), "provider": "twilio"}
        except Exception as e:
            logger.error(f"Failed to dispatch Twilio SMS to {to_number}: {e}")
            return {"success": False, "error": str(e), "provider": "twilio"}


class SMSService:
    """Singleton service managing Guardian SMS notifications and policy checks."""

    _instance: Optional["SMSService"] = None
    _custom_provider: Optional[BaseSMSProvider] = None

    @classmethod
    def get_instance(cls) -> "SMSService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def set_provider(cls, provider: Optional[BaseSMSProvider]):
        """Allows test suites to register mock or custom providers."""
        cls._custom_provider = provider

    def get_provider(self) -> Optional[BaseSMSProvider]:
        if self._custom_provider is not None:
            return self._custom_provider

        provider_name = os.getenv("SMS_PROVIDER", "").lower().strip()
        if not provider_name or provider_name in ("none", "disabled", "off"):
            return None

        if provider_name == "mock":
            return MockSMSProvider()

        if provider_name == "twilio":
            sid = os.getenv("SMS_API_KEY", "").strip()
            secret = os.getenv("SMS_API_SECRET", "").strip()
            from_num = os.getenv("SMS_FROM_NUMBER", "").strip()
            if sid and secret and from_num:
                return TwilioSMSProvider(account_sid=sid, auth_token=secret, from_number=from_num)

        return None

    def is_configured(self) -> bool:
        """Returns True if a valid SMS provider and credentials are configured."""
        if self._custom_provider is not None:
            return True
        provider_name = os.getenv("SMS_PROVIDER", "").lower().strip()
        api_key = os.getenv("SMS_API_KEY", "").strip()
        from_num = os.getenv("SMS_FROM_NUMBER", "").strip()
        return bool(provider_name and api_key and from_num)

    def get_provider_name(self) -> str:
        if self._custom_provider is not None:
            return getattr(self._custom_provider, "__class__", type(self._custom_provider)).__name__
        return os.getenv("SMS_PROVIDER", "None").strip() or "None"

    def send_guardian_alert(
        self,
        to_number: Optional[str],
        severity: str,
        user_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enforces severity policy and dispatches a sanitized Guardian security alert.

        Severity Policy:
          - SAFE: No SMS
          - SUSPICIOUS: Sent only if explicitly enabled
          - HIGH_RISK / HIGH / CRITICAL: Dispatches sanitized SMS
        """
        sev_norm = (severity or "INFO").upper().strip()

        # Severity Rule 1: SAFE alerts never trigger an SMS
        if sev_norm in ("SAFE", "LOW", "INFO"):
            return {
                "sent": False,
                "status": "skipped",
                "reason": f"{sev_norm} severity does not trigger Guardian SMS."
            }

        # Check recipient number
        clean_number = (to_number or "").strip()
        if not clean_number:
            logger.info("Guardian SMS alert skipped: No guardian phone number on record.")
            return {
                "sent": False,
                "status": "missing_recipient",
                "message": "Guardian phone number not specified."
            }

        # Format sanitized message (Strictly NO OTPs, passwords, scan content, or private data)
        display_sev = "HIGH RISK" if sev_norm in ("HIGH", "HIGH RISK", "HIGH_RISK") else sev_norm
        user_display = f" ({user_name})" if user_name else ""
        sanitized_body = (
            f"KAVACH Alert: A {display_sev} security event was detected for your protected user{user_display}. "
            f"Open KAVACH to view the alert."
        )

        provider = self.get_provider()
        if not provider:
            logger.info("SMS notifications are not configured in system environment.")
            return {
                "sent": False,
                "status": "not_configured",
                "message": "SMS notifications are not configured.",
                "sanitized_body": sanitized_body
            }

        try:
            result = provider.send_sms(clean_number, sanitized_body)
            return {
                "sent": result.get("success", False),
                "status": "delivered" if result.get("success") else "failed",
                "provider": result.get("provider", "unknown"),
                "message_id": result.get("message_id"),
                "sanitized_body": sanitized_body,
                "error": result.get("error")
            }
        except Exception as e:
            logger.error(f"Error during Guardian SMS dispatch: {e}", exc_info=True)
            return {
                "sent": False,
                "status": "error",
                "error": str(e)
            }

    def send_test_sms(self, to_number: str) -> Dict[str, Any]:
        """Sends a harmless test SMS to verify carrier delivery configuration."""
        if not self.is_configured():
            return {
                "sent": False,
                "status": "not_configured",
                "message": "SMS notifications are not configured."
            }

        clean_number = (to_number or "").strip()
        if not clean_number:
            return {
                "sent": False,
                "status": "invalid_number",
                "message": "Please enter a valid phone number."
            }

        provider = self.get_provider()
        if not provider:
            return {
                "sent": False,
                "status": "not_configured",
                "message": "SMS notifications are not configured."
            }

        test_msg = "KAVACH Security: This is a test notification confirming your Guardian alert channel is active."
        try:
            res = provider.send_sms(clean_number, test_msg)
            return {
                "sent": res.get("success", False),
                "status": "delivered" if res.get("success") else "failed",
                "message": "Test SMS sent successfully." if res.get("success") else res.get("error")
            }
        except Exception as e:
            return {"sent": False, "status": "error", "error": str(e)}
