"""
=============================================================================
KAVACH — Guardian Notification & System Alert Integration Service
=============================================================================
Orchestrates:
  - Ingestion of high-risk / critical SecurityAlert events
  - Automated insertion of sanitized SYSTEM_ALERT messages into the Guardian chat
  - Prevention of duplicate alert messages for the same incident
  - Evaluation of Guardian SMS severity policies and dispatch via SMSService
  - Real-time WebSocket broadcasting to connected chat peers
=============================================================================
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.models.guardian import GuardianAccess
from app.models.guardian_chat import GuardianConversation, GuardianMessage
from app.models.incident_report import IncidentReport
from app.models.security_alert import SecurityAlert
from app.models.user import User
from app.services.sms_service import SMSService

logger = logging.getLogger("kavach.services.guardian_notification")


def get_or_create_guardian_conversation(db: Session, user_id: int) -> GuardianConversation:
    """Finds or initializes the unique GuardianConversation record for a protected user."""
    conv = db.query(GuardianConversation).filter(GuardianConversation.user_id == user_id).first()
    if not conv:
        # Check if active guardian access exists
        now = datetime.now(timezone.utc)
        active_access = db.query(GuardianAccess).filter(
            GuardianAccess.user_id == user_id,
            GuardianAccess.is_active == True,
            GuardianAccess.expires_at > now
        ).first()

        conv = GuardianConversation(
            user_id=user_id,
            guardian_id=active_access.id if active_access else None,
            sms_high_risk=True,
            sms_critical=True,
            sms_suspicious=False,
        )
        db.add(conv)
        db.commit()
        db.refresh(conv)
    return conv


def handle_security_alert_notification(
    db: Session,
    alert: SecurityAlert,
    custom_explanation: Optional[str] = None
) -> Optional[GuardianMessage]:
    """
    Called when a SecurityAlert is registered.
    If the alert is HIGH or CRITICAL severity (or matches policy):
      1. Finds or creates the User's GuardianConversation
      2. Ensures no duplicate SYSTEM_ALERT message exists for alert.id
      3. Creates a sanitized GuardianMessage of type SYSTEM_ALERT
      4. Invokes SMSService if SMS policy is satisfied
      5. Broadcasts event over WebSocket if active
    """
    if not alert or not alert.id:
        return None

    try:
        user_id = alert.user_id
        severity = (alert.severity or "INFO").upper().strip()

        # Check if alert meets threshold for Guardian notification (HIGH or CRITICAL or SUSPICIOUS)
        if severity not in ("HIGH", "HIGH_RISK", "HIGH RISK", "CRITICAL", "SUSPICIOUS"):
            return None

        conv = get_or_create_guardian_conversation(db, user_id)

        # Check for duplicate system message for the same alert_id
        existing_msg = db.query(GuardianMessage).filter(
            GuardianMessage.conversation_id == conv.id,
            GuardianMessage.alert_id == alert.id
        ).first()

        if existing_msg:
            logger.info(f"System alert for alert #{alert.id} already exists in conversation #{conv.id}. Skipping duplicate.")
            return existing_msg

        # Retrieve any linked IncidentReport
        report = db.query(IncidentReport).filter(IncidentReport.security_alert_id == alert.id).first()
        report_id = report.report_id if report else None

        # Build sanitized explanation (No passwords, tokens, or raw scans)
        sanitized_summary = alert.message or "A high-risk security threat was flagged by KAVACH Sentinels."
        if custom_explanation:
            sanitized_summary = f"{sanitized_summary} Note: {custom_explanation}"

        # Create the system alert chat message
        system_message = GuardianMessage(
            conversation_id=conv.id,
            sender_id=0,
            sender_role="system",
            message_type="SYSTEM_ALERT",
            text_content=sanitized_summary,
            alert_id=alert.id,
            is_read=False,
            created_at=datetime.now(timezone.utc)
        )
        db.add(system_message)
        conv.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(system_message)

        # Dispatch Guardian SMS according to severity settings
        should_send_sms = False
        if severity in ("CRITICAL",) and conv.sms_critical:
            should_send_sms = True
        elif severity in ("HIGH", "HIGH_RISK", "HIGH RISK") and conv.sms_high_risk:
            should_send_sms = True
        elif severity in ("SUSPICIOUS",) and conv.sms_suspicious:
            should_send_sms = True

        if should_send_sms and conv.guardian_phone:
            user = db.query(User).filter(User.id == user_id).first()
            user_name = user.full_name if user else None
            sms_service = SMSService.get_instance()
            sms_service.send_guardian_alert(
                to_number=conv.guardian_phone,
                severity=severity,
                user_name=user_name
            )

        # Broadcast via WebSocket if real-time router has active subscribers
        try:
            from app.api.guardian_chat import broadcast_chat_event
            broadcast_chat_event(conv.id, {
                "type": "new_message",
                "message": {
                    "id": system_message.id,
                    "conversation_id": conv.id,
                    "sender_id": 0,
                    "sender_role": "system",
                    "message_type": "SYSTEM_ALERT",
                    "text_content": system_message.text_content,
                    "alert_id": alert.id,
                    "alert_severity": alert.severity,
                    "alert_title": alert.title,
                    "incident_report_id": report_id,
                    "is_read": False,
                    "created_at": system_message.created_at.isoformat(),
                }
            })
        except Exception as ws_err:
            logger.debug(f"Chat WebSocket broadcast bypassed: {ws_err}")

        return system_message

    except Exception as e:
        logger.error(f"Error handling Guardian security alert notification: {e}", exc_info=True)
        return None
