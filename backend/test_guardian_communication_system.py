"""
=============================================================================
KAVACH — Guardian Communication System Comprehensive Test Suite
=============================================================================
Validates:
  1. User creates/accesses Guardian conversation.
  2. Guardian accesses linked User conversation.
  3. Unlinked Guardian cannot access conversation.
  4. User sends text message.
  5. Guardian sends text message.
  6. User sends voice message.
  7. Guardian sends voice message.
  8. Voice file validation (rejects invalid format/empty bytes).
  9. Unauthorized voice-file access is rejected (403/404).
  10. Message read status (auto-read and manual PATCH).
  11. HIGH_RISK alert creates Guardian system message.
  12. Duplicate alert does not create duplicate chat message.
  13. SAFE alert does not create Guardian SMS.
  14. HIGH_RISK triggers SMS service when configured.
  15. CRITICAL triggers SMS service when configured.
  16. SMS is not sent when disabled.
  17. SMS content is sanitized (strictly no OTP, password, token, or scan text).
  18. Missing SMS configuration does not crash the security alert system.
=============================================================================
"""

import io
import os
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.guardian import GuardianAccess
from app.models.guardian_chat import GuardianConversation, GuardianMessage
from app.models.security_alert import SecurityAlert
from app.services.sms_service import SMSService, MockSMSProvider
from app.services.guardian_notification_service import handle_security_alert_notification
from app.utils.security import create_access_token

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_guardian_chat_data():
    """Sets up primary guarded user, second unrelated user, and active/inactive guardian access records."""
    db = SessionLocal()
    try:
        # User 1 (Guarded User)
        u1 = db.query(User).filter(User.email == "gcomm_user1@kavach.ai").first()
        if not u1:
            u1 = User(
                full_name="Guarded User Alpha",
                email="gcomm_user1@kavach.ai",
                password="hashed_pwd_alpha_123",
                role="user"
            )
            db.add(u1)
            db.commit()
            db.refresh(u1)

        # User 2 (Unrelated User)
        u2 = db.query(User).filter(User.email == "gcomm_user2@kavach.ai").first()
        if not u2:
            u2 = User(
                full_name="Unrelated User Beta",
                email="gcomm_user2@kavach.ai",
                password="hashed_pwd_beta_456",
                role="user"
            )
            db.add(u2)
            db.commit()
            db.refresh(u2)

        # Active Guardian Access for User 1
        now = datetime.now(timezone.utc)
        g_access = db.query(GuardianAccess).filter(
            GuardianAccess.user_id == u1.id,
            GuardianAccess.is_active == True,
            GuardianAccess.expires_at > now
        ).first()

        if not g_access:
            g_access = GuardianAccess(
                user_id=u1.id,
                code_hash="fake_guardian_code_hash_1",
                is_active=True,
                expires_at=now + timedelta(hours=24)
            )
            db.add(g_access)
            db.commit()
            db.refresh(g_access)

        # Inactive/Expired Guardian Access for User 2
        g_access_expired = GuardianAccess(
            user_id=u2.id,
            code_hash="expired_guardian_code_hash_2",
            is_active=False,
            expires_at=now - timedelta(hours=2),
            revoked_at=now - timedelta(hours=2)
        )
        db.add(g_access_expired)
        db.commit()
        db.refresh(g_access_expired)

        token_u1 = create_access_token({"sub": str(u1.id), "role": "user"})
        token_u2 = create_access_token({"sub": str(u2.id), "role": "user"})
        token_g1 = create_access_token({
            "sub": str(u1.id),
            "role": "guardian",
            "guardian_access_id": g_access.id
        })
        token_unlinked_g = create_access_token({
            "sub": str(u2.id),
            "role": "guardian",
            "guardian_access_id": g_access_expired.id
        })

        return {
            "u1": u1,
            "u2": u2,
            "g_access": g_access,
            "token_u1": token_u1,
            "token_u2": token_u2,
            "token_g1": token_g1,
            "token_unlinked_g": token_unlinked_g,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 1. USER CREATES / ACCESSES CONVERSATION
# ---------------------------------------------------------------------------
def test_01_user_creates_and_accesses_conversation(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers = {"Authorization": f"Bearer {data['token_u1']}"}

    res = client.get("/guardian-chat/conversations", headers=headers)
    assert res.status_code == 200
    conv = res.json()
    assert conv["user_id"] == data["u1"].id
    assert conv["is_guardian_linked"] is True
    assert "id" in conv
    assert conv["guarded_user"]["full_name"] == data["u1"].full_name


# ---------------------------------------------------------------------------
# 2. GUARDIAN ACCESSES LINKED USER CONVERSATION
# ---------------------------------------------------------------------------
def test_02_guardian_accesses_linked_user_conversation(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers = {"Authorization": f"Bearer {data['token_g1']}"}

    res = client.get("/guardian-chat/conversations", headers=headers)
    assert res.status_code == 200
    conv = res.json()
    assert conv["user_id"] == data["u1"].id
    assert conv["is_guardian_linked"] is True


# ---------------------------------------------------------------------------
# 3. UNLINKED / EXPIRED GUARDIAN ACCESS IS REJECTED
# ---------------------------------------------------------------------------
def test_03_unlinked_guardian_cannot_access_conversation(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_unlinked = {"Authorization": f"Bearer {data['token_unlinked_g']}"}

    # Should be rejected because access code expired / is inactive
    res = client.get("/guardian-chat/conversations", headers=headers_unlinked)
    assert res.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 4. USER SENDS TEXT MESSAGE
# ---------------------------------------------------------------------------
def test_04_user_sends_text_message(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_u1 = {"Authorization": f"Bearer {data['token_u1']}"}

    conv = client.get("/guardian-chat/conversations", headers=headers_u1).json()
    conv_id = conv["id"]

    text_body = {"text": "Hello Guardian, is everything secure with my account today?"}
    res = client.post(f"/guardian-chat/conversations/{conv_id}/messages", headers=headers_u1, json=text_body)
    assert res.status_code == 200
    msg = res.json()
    assert msg["conversation_id"] == conv_id
    assert msg["sender_role"] == "user"
    assert msg["text_content"] == text_body["text"]
    assert msg["message_type"] == "TEXT"
    assert msg["is_read"] is False


# ---------------------------------------------------------------------------
# 5. GUARDIAN SENDS TEXT MESSAGE
# ---------------------------------------------------------------------------
def test_05_guardian_sends_text_message(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_g1 = {"Authorization": f"Bearer {data['token_g1']}"}

    conv = client.get("/guardian-chat/conversations", headers=headers_g1).json()
    conv_id = conv["id"]

    text_body = {"text": "Yes, I am monitoring your telemetry. All safe."}
    res = client.post(f"/guardian-chat/conversations/{conv_id}/messages", headers=headers_g1, json=text_body)
    assert res.status_code == 200
    msg = res.json()
    assert msg["conversation_id"] == conv_id
    assert msg["sender_role"] == "guardian"
    assert msg["text_content"] == text_body["text"]
    assert msg["message_type"] == "TEXT"


# ---------------------------------------------------------------------------
# 6. USER SENDS VOICE MESSAGE
# ---------------------------------------------------------------------------
def test_06_user_sends_voice_message(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_u1 = {"Authorization": f"Bearer {data['token_u1']}"}

    conv = client.get("/guardian-chat/conversations", headers=headers_u1).json()
    conv_id = conv["id"]

    fake_webm_bytes = b"\x1aE\xdf\xa3fake-webm-audio-voice-note-data-payload-bytes"
    files = {"file": ("voice_note.webm", io.BytesIO(fake_webm_bytes), "audio/webm")}
    form_data = {"duration": "14.2"}

    res = client.post(
        f"/guardian-chat/conversations/{conv_id}/voice",
        headers=headers_u1,
        files=files,
        data=form_data
    )
    assert res.status_code == 200
    vmsg = res.json()
    assert vmsg["conversation_id"] == conv_id
    assert vmsg["sender_role"] == "user"
    assert vmsg["message_type"] == "VOICE"
    assert vmsg["voice_duration"] == 14.2
    assert vmsg["has_voice"] is True
    assert vmsg["voice_url"] is not None


# ---------------------------------------------------------------------------
# 7. GUARDIAN SENDS VOICE MESSAGE
# ---------------------------------------------------------------------------
def test_07_guardian_sends_voice_message(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_g1 = {"Authorization": f"Bearer {data['token_g1']}"}

    conv = client.get("/guardian-chat/conversations", headers=headers_g1).json()
    conv_id = conv["id"]

    fake_wav_bytes = b"RIFFfake-wav-voice-data-from-guardian"
    files = {"file": ("guardian_reply.wav", io.BytesIO(fake_wav_bytes), "audio/wav")}
    form_data = {"duration": "8.5"}

    res = client.post(
        f"/guardian-chat/conversations/{conv_id}/voice",
        headers=headers_g1,
        files=files,
        data=form_data
    )
    assert res.status_code == 200
    vmsg = res.json()
    assert vmsg["conversation_id"] == conv_id
    assert vmsg["sender_role"] == "guardian"
    assert vmsg["message_type"] == "VOICE"
    assert vmsg["voice_duration"] == 8.5


# ---------------------------------------------------------------------------
# 8. VOICE FILE VALIDATION
# ---------------------------------------------------------------------------
def test_08_voice_file_validation_rejects_empty_or_executable(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_u1 = {"Authorization": f"Bearer {data['token_u1']}"}

    conv = client.get("/guardian-chat/conversations", headers=headers_u1).json()
    conv_id = conv["id"]

    # 1. Reject empty file
    files_empty = {"file": ("empty.webm", io.BytesIO(b""), "audio/webm")}
    res_empty = client.post(f"/guardian-chat/conversations/{conv_id}/voice", headers=headers_u1, files=files_empty)
    assert res_empty.status_code == 400

    # 2. Reject arbitrary executable/script file
    files_exe = {"file": ("exploit.exe", io.BytesIO(b"MZ\x90fake-executable"), "application/x-msdownload")}
    res_exe = client.post(f"/guardian-chat/conversations/{conv_id}/voice", headers=headers_u1, files=files_exe)
    assert res_exe.status_code == 400


# ---------------------------------------------------------------------------
# 9. UNAUTHORIZED VOICE-FILE ACCESS IS REJECTED
# ---------------------------------------------------------------------------
def test_09_unauthorized_voice_file_access_rejected(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_u1 = {"Authorization": f"Bearer {data['token_u1']}"}
    headers_u2 = {"Authorization": f"Bearer {data['token_u2']}"}  # User 2 (unrelated)

    # User 1 sends a voice message
    conv = client.get("/guardian-chat/conversations", headers=headers_u1).json()
    conv_id = conv["id"]
    files = {"file": ("private_audio.webm", io.BytesIO(b"\x1aE\xdf\xa3sample-bytes"), "audio/webm")}
    vmsg = client.post(f"/guardian-chat/conversations/{conv_id}/voice", headers=headers_u1, files=files).json()
    vmsg_id = vmsg["id"]

    # User 1 can download/stream their own voice note
    res_u1 = client.get(f"/guardian-chat/messages/{vmsg_id}/voice", headers=headers_u1)
    assert res_u1.status_code == 200

    # User 2 (unrelated) is strictly rejected (403 Forbidden or 404 Not Found)
    res_u2 = client.get(f"/guardian-chat/messages/{vmsg_id}/voice", headers=headers_u2)
    assert res_u2.status_code in (403, 404)


# ---------------------------------------------------------------------------
# 10. MESSAGE READ STATUS
# ---------------------------------------------------------------------------
def test_10_message_read_status(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    headers_u1 = {"Authorization": f"Bearer {data['token_u1']}"}
    headers_g1 = {"Authorization": f"Bearer {data['token_g1']}"}

    conv = client.get("/guardian-chat/conversations", headers=headers_u1).json()
    conv_id = conv["id"]

    # User sends text
    res = client.post(
        f"/guardian-chat/conversations/{conv_id}/messages",
        headers=headers_u1,
        json={"text": "Unread message check"}
    )
    msg_id = res.json()["id"]

    # Guardian fetches conversation messages -> marks user messages as read
    messages = client.get(f"/guardian-chat/conversations/{conv_id}/messages", headers=headers_g1).json()
    found = next((m for m in messages if m["id"] == msg_id), None)
    assert found is not None
    assert found["is_read"] is True

    # Manual patch read test
    patch_res = client.patch(f"/guardian-chat/messages/{msg_id}/read", headers=headers_g1)
    assert patch_res.status_code == 200


# ---------------------------------------------------------------------------
# 11. HIGH_RISK ALERT CREATES GUARDIAN SYSTEM MESSAGE
# ---------------------------------------------------------------------------
def test_11_high_risk_alert_creates_system_message(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    db = SessionLocal()
    try:
        alert = SecurityAlert(
            user_id=data["u1"].id,
            alert_type="link_scam",
            title="High-Risk Phishing Link Flagged",
            message="KAVACH detected high-risk phishing URL attempting to harvest credentials.",
            severity="HIGH",
            is_read=False
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        sys_msg = handle_security_alert_notification(db, alert)
        assert sys_msg is not None
        assert sys_msg.message_type == "SYSTEM_ALERT"
        assert sys_msg.sender_role == "system"
        assert sys_msg.alert_id == alert.id
        assert "phishing" in sys_msg.text_content.lower()

        # Check guardian sees this message in chat
        headers_g1 = {"Authorization": f"Bearer {data['token_g1']}"}
        conv = client.get("/guardian-chat/conversations", headers=headers_g1).json()
        messages = client.get(f"/guardian-chat/conversations/{conv['id']}/messages", headers=headers_g1).json()
        alert_in_chat = next((m for m in messages if m["alert_id"] == alert.id), None)
        assert alert_in_chat is not None
        assert alert_in_chat["message_type"] == "SYSTEM_ALERT"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 12. DUPLICATE ALERT DOES NOT CREATE DUPLICATE CHAT MESSAGE
# ---------------------------------------------------------------------------
def test_12_duplicate_alert_does_not_create_duplicate_message(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    db = SessionLocal()
    try:
        alert = SecurityAlert(
            user_id=data["u1"].id,
            alert_type="document_scam",
            title="Malicious APK Document",
            message="Document contains malicious trojan dropper indicators.",
            severity="HIGH",
            is_read=False
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Call twice with same alert
        msg1 = handle_security_alert_notification(db, alert)
        msg2 = handle_security_alert_notification(db, alert)

        assert msg1.id == msg2.id

        # Verify only one message exists in DB with this alert_id
        count = db.query(GuardianMessage).filter(GuardianMessage.alert_id == alert.id).count()
        assert count == 1
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 13. SAFE ALERT DOES NOT CREATE GUARDIAN SMS
# ---------------------------------------------------------------------------
def test_13_safe_alert_does_not_create_guardian_sms(setup_guardian_chat_data):
    mock_provider = MockSMSProvider()
    SMSService.set_provider(mock_provider)

    sms_service = SMSService.get_instance()
    res = sms_service.send_guardian_alert(
        to_number="+15550001111",
        severity="SAFE",
        user_name="Alpha User"
    )

    assert res["sent"] is False
    assert res["status"] == "skipped"
    assert len(mock_provider.sent_messages) == 0


# ---------------------------------------------------------------------------
# 14. HIGH_RISK TRIGGERS SMS SERVICE WHEN CONFIGURED
# ---------------------------------------------------------------------------
def test_14_high_risk_triggers_sms_when_configured():
    mock_provider = MockSMSProvider()
    SMSService.set_provider(mock_provider)

    sms_service = SMSService.get_instance()
    res = sms_service.send_guardian_alert(
        to_number="+15559876543",
        severity="HIGH RISK",
        user_name="Protected Caller"
    )

    assert res["sent"] is True
    assert res["status"] == "delivered"
    assert len(mock_provider.sent_messages) == 1
    sent = mock_provider.sent_messages[0]
    assert sent["to"] == "+15559876543"
    assert "HIGH RISK" in sent["message"]


# ---------------------------------------------------------------------------
# 15. CRITICAL TRIGGERS SMS SERVICE WHEN CONFIGURED
# ---------------------------------------------------------------------------
def test_15_critical_triggers_sms_when_configured():
    mock_provider = MockSMSProvider()
    SMSService.set_provider(mock_provider)

    sms_service = SMSService.get_instance()
    res = sms_service.send_guardian_alert(
        to_number="+15559876543",
        severity="CRITICAL",
        user_name="Guarded Senior"
    )

    assert res["sent"] is True
    assert res["status"] == "delivered"
    assert any("CRITICAL" in m["message"] for m in mock_provider.sent_messages)


# ---------------------------------------------------------------------------
# 16. SMS IS NOT SENT WHEN DISABLED IN SETTINGS
# ---------------------------------------------------------------------------
def test_16_sms_not_sent_when_disabled_in_settings(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    mock_provider = MockSMSProvider()
    SMSService.set_provider(mock_provider)

    headers_g1 = {"Authorization": f"Bearer {data['token_g1']}"}

    # Guardian disables HIGH RISK SMS notifications
    patch_res = client.patch(
        "/guardian-chat/settings",
        headers=headers_g1,
        json={"sms_high_risk": False, "guardian_phone": "+15559990000"}
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["sms_high_risk"] is False

    initial_count = len(mock_provider.sent_messages)

    # Create a HIGH alert
    db = SessionLocal()
    try:
        alert = SecurityAlert(
            user_id=data["u1"].id,
            alert_type="message_scam",
            title="Disabled SMS High Risk Alert",
            message="Test alert message",
            severity="HIGH",
            is_read=False
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        handle_security_alert_notification(db, alert)

        # No new SMS should have been added because sms_high_risk was False
        assert len(mock_provider.sent_messages) == initial_count
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 17. SMS CONTENT IS SANITIZED
# ---------------------------------------------------------------------------
def test_17_sms_content_is_strictly_sanitized():
    mock_provider = MockSMSProvider()
    SMSService.set_provider(mock_provider)

    sms_service = SMSService.get_instance()
    res = sms_service.send_guardian_alert(
        to_number="+15551234567",
        severity="HIGH",
        user_name="John Doe"
    )

    body = res["sanitized_body"]
    # Verify strict sanitization: no OTPs, passwords, auth tokens, or private texts
    for forbidden in ["password", "otp", "token", "secret", "cvv", "bearer", "http"]:
        assert forbidden not in body.lower(), f"Forbidden substring '{forbidden}' leaked into SMS body!"

    assert "KAVACH Alert:" in body
    assert "Open KAVACH to view the alert." in body


# ---------------------------------------------------------------------------
# 18. MISSING SMS CONFIGURATION DOES NOT CRASH SECURITY ALERT SYSTEM
# ---------------------------------------------------------------------------
def test_18_missing_sms_configuration_does_not_crash(setup_guardian_chat_data):
    data = setup_guardian_chat_data
    # Clear any provider to simulate unconfigured environment
    SMSService.set_provider(None)

    db = SessionLocal()
    try:
        alert = SecurityAlert(
            user_id=data["u1"].id,
            alert_type="voice_vishing_scam",
            title="Voice Vishing Critical Scam",
            message="Critical vishing scam detected in active voice stream.",
            severity="CRITICAL",
            is_read=False
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Even with zero SMS configuration, this function must succeed and return the chat message
        sys_msg = handle_security_alert_notification(db, alert)
        assert sys_msg is not None
        assert sys_msg.alert_id == alert.id
        assert sys_msg.message_type == "SYSTEM_ALERT"

        # Also test direct test endpoint returns clean non-crash status
        headers_g1 = {"Authorization": f"Bearer {data['token_g1']}"}
        test_res = client.post("/guardian-chat/send-test-sms", headers=headers_g1, json={"phone_number": "+15550000"})
        assert test_res.status_code == 200
        assert test_res.json()["status"] == "not_configured"
        assert "not configured" in test_res.json()["message"].lower()
    finally:
        db.close()
