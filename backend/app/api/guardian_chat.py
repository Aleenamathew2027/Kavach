"""
=============================================================================
KAVACH — Guardian Communication System API Router
=============================================================================
Endpoints for private messaging between Protected Users and verified Guardians:
  - GET/POST /guardian-chat/conversations
  - GET      /guardian-chat/conversations/{id}/messages
  - POST     /guardian-chat/conversations/{id}/messages (Text Message)
  - POST     /guardian-chat/conversations/{id}/voice    (Recorded Voice Message)
  - GET      /guardian-chat/messages/{id}/voice        (Secure Voice Audio Stream)
  - PATCH    /guardian-chat/messages/{id}/read         (Mark Message Read)
  - GET/PATCH/guardian-chat/settings                   (Guardian SMS & Alert Settings)
  - POST     /guardian-chat/send-test-sms              (Carrier Test SMS)
  - WS       /guardian-chat/ws/{conversation_id}       (Real-Time Event Distribution)
=============================================================================
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import uuid
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.models.guardian import GuardianAccess
from app.models.guardian_chat import GuardianConversation, GuardianMessage
from app.models.incident_report import IncidentReport
from app.models.security_alert import SecurityAlert
from app.models.user import User
from app.schemas.guardian_chat_schema import (
    GuardianConversationResponse,
    GuardianMessageResponse,
    GuardianSettingsResponse,
    GuardianSettingsUpdateRequest,
    SendTextMessageRequest,
    SendTestSMSRequest,
)
from app.services.guardian_notification_service import get_or_create_guardian_conversation
from app.services.sms_service import SMSService
from app.utils.security import get_db, require_role

logger = logging.getLogger("kavach.api.guardian_chat")

router = APIRouter(
    prefix="/guardian-chat",
    tags=["Guardian Private Communication System"]
)

# Base directory for storing recorded voice notes securely on disk
VOICE_STORAGE_DIR = Path(__file__).resolve().parent.parent.parent / "uploads" / "guardian_voice"
VOICE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Active WebSocket connections grouped by conversation_id
_chat_ws_connections: Dict[int, List[WebSocket]] = {}


def broadcast_chat_event(conversation_id: int, event_payload: Dict[str, Any]):
    """Broadcasts a JSON chat event to active WebSocket connections for this conversation."""
    ws_list = _chat_ws_connections.get(conversation_id, [])
    if not ws_list:
        return
    raw_text = json.dumps(event_payload)
    for ws in list(ws_list):
        try:
            asyncio.create_task(ws.send_text(raw_text))
        except Exception:
            pass


def _verify_conversation_access(
    auth_ctx: dict,
    conversation: GuardianConversation,
    db: Session
) -> tuple[int, str]:
    """
    Enforces strict role-based access control and relationship verification:
      - 'user' role can only access conversations where conversation.user_id == user.id
      - 'guardian' role can only access conversations where conversation.user_id == guarded_user_id
    Returns: (caller_id, caller_role)
    """
    role = auth_ctx["role"]
    payload = auth_ctx["payload"]

    if role == "user":
        user: User = auth_ctx["user"]
        if conversation.user_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view this conversation."
            )
        return user.id, "user"

    elif role == "guardian":
        guarded_user_id = int(payload["sub"])
        guardian_access_id = payload.get("guardian_access_id")

        if conversation.user_id != guarded_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You can only communicate with your linked protected user."
            )

        # Check guardian authorization active status
        if guardian_access_id:
            now = datetime.now(timezone.utc)
            access = db.query(GuardianAccess).filter(
                GuardianAccess.id == guardian_access_id,
                GuardianAccess.is_active == True,
                GuardianAccess.expires_at > now
            ).first()
            if not access:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Guardian authorization code has expired or been revoked."
                )

        return (guardian_access_id or conversation.guardian_id or 0), "guardian"

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized role.")


def _serialize_message(msg: GuardianMessage, db: Session) -> Dict[str, Any]:
    incident_report_id = None
    alert_severity = None
    alert_title = None

    if msg.alert_id:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == msg.alert_id).first()
        if alert:
            alert_severity = alert.severity
            alert_title = alert.title
            report = db.query(IncidentReport).filter(IncidentReport.security_alert_id == alert.id).first()
            if report:
                incident_report_id = report.report_id

    voice_url = f"/guardian-chat/messages/{msg.id}/voice" if msg.voice_file_path else None

    return {
        "id": msg.id,
        "conversation_id": msg.conversation_id,
        "sender_id": msg.sender_id,
        "sender_role": msg.sender_role,
        "message_type": msg.message_type,
        "text_content": msg.text_content,
        "voice_duration": msg.voice_duration,
        "has_voice": bool(msg.voice_file_path),
        "voice_url": voice_url,
        "alert_id": msg.alert_id,
        "alert_severity": alert_severity,
        "alert_title": alert_title,
        "incident_report_id": incident_report_id,
        "is_read": msg.is_read,
        "created_at": msg.created_at.isoformat() if msg.created_at else datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. CONVERSATION LIFECYCLE
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/conversations",
    response_model=GuardianConversationResponse,
    summary="Get active Guardian ↔ User private conversation metadata"
)
@router.get(
    "/conversation",
    response_model=GuardianConversationResponse,
    summary="Get active Guardian ↔ User private conversation metadata (alias)"
)
def get_conversation(
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    role = auth_ctx["role"]
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])

    conv = get_or_create_guardian_conversation(db, user_id)
    caller_id, caller_role = _verify_conversation_access(auth_ctx, conv, db)

    # Check if active guardian access exists
    now = datetime.now(timezone.utc)
    active_access = db.query(GuardianAccess).filter(
        GuardianAccess.user_id == user_id,
        GuardianAccess.is_active == True,
        GuardianAccess.expires_at > now
    ).first()

    # Calculate unread count (messages sent by other party not yet read)
    unread_count = db.query(GuardianMessage).filter(
        GuardianMessage.conversation_id == conv.id,
        GuardianMessage.is_read == False,
        GuardianMessage.sender_role != caller_role
    ).count()

    user = db.query(User).filter(User.id == user_id).first()

    return GuardianConversationResponse(
        id=conv.id,
        user_id=conv.user_id,
        guarded_user={
            "id": user.id if user else user_id,
            "full_name": user.full_name if user else "Protected User",
            "email": user.email if user else "",
        },
        is_guardian_linked=bool(active_access is not None),
        unread_count=unread_count,
        sms_high_risk=conv.sms_high_risk,
        sms_critical=conv.sms_critical,
        sms_suspicious=conv.sms_suspicious,
        guardian_phone=conv.guardian_phone,
        created_at=conv.created_at.isoformat(),
        updated_at=conv.updated_at.isoformat() if conv.updated_at else conv.created_at.isoformat(),
    )


@router.post(
    "/conversations",
    response_model=GuardianConversationResponse,
    summary="Create or retrieve active Guardian ↔ User private conversation"
)
def create_conversation(
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    return get_conversation(auth_ctx=auth_ctx, db=db)


# ─────────────────────────────────────────────────────────────────────────────
# 2. MESSAGES (TEXT & LISTING)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=List[GuardianMessageResponse],
    summary="Retrieve chronological messages for private Guardian conversation"
)
def list_messages(
    conversation_id: int,
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    conv = db.query(GuardianConversation).filter(GuardianConversation.id == conversation_id).first()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found.")

    caller_id, caller_role = _verify_conversation_access(auth_ctx, conv, db)

    # Mark incoming messages as read
    db.query(GuardianMessage).filter(
        GuardianMessage.conversation_id == conv.id,
        GuardianMessage.is_read == False,
        GuardianMessage.sender_role != caller_role
    ).update({"is_read": True})
    db.commit()

    messages = db.query(GuardianMessage).filter(
        GuardianMessage.conversation_id == conv.id
    ).order_by(GuardianMessage.created_at.asc()).all()

    return [_serialize_message(m, db) for m in messages]


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=GuardianMessageResponse,
    summary="Send a normal private text message in Guardian conversation"
)
def send_text_message(
    conversation_id: int,
    body: SendTextMessageRequest,
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    conv = db.query(GuardianConversation).filter(GuardianConversation.id == conversation_id).first()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found.")

    caller_id, caller_role = _verify_conversation_access(auth_ctx, conv, db)

    text_clean = body.text.strip()
    if not text_clean:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message content cannot be blank.")

    message = GuardianMessage(
        conversation_id=conv.id,
        sender_id=caller_id,
        sender_role=caller_role,
        message_type="TEXT",
        text_content=text_clean,
        is_read=False,
        created_at=datetime.now(timezone.utc)
    )
    db.add(message)
    conv.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(message)

    serialized = _serialize_message(message, db)
    broadcast_chat_event(conv.id, {"type": "new_message", "message": serialized})

    return serialized


# ─────────────────────────────────────────────────────────────────────────────
# 3. VOICE MESSAGES (RECORDING UPLOAD & STREAMING)
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/conversations/{conversation_id}/voice",
    response_model=GuardianMessageResponse,
    summary="Upload and send a recorded voice message in private Guardian chat"
)
async def send_voice_message(
    conversation_id: int,
    file: UploadFile = File(...),
    duration: Optional[float] = Form(None),
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    conv = db.query(GuardianConversation).filter(GuardianConversation.id == conversation_id).first()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found.")

    caller_id, caller_role = _verify_conversation_access(auth_ctx, conv, db)

    # 1. Validate file size (Max 15MB)
    audio_bytes = await file.read()
    if len(audio_bytes) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty audio file provided.")
    if len(audio_bytes) > 15 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Voice file exceeds 15MB limit.")

    # 2. Validate MIME type & file extension (Disallow executable or arbitrary uploads)
    content_type = (file.content_type or "").lower()
    filename = (file.filename or "").lower()
    allowed_exts = (".webm", ".ogg", ".wav", ".mp3", ".m4a", ".mp4", ".aac")
    is_audio_type = content_type.startswith("audio/") or content_type in ("video/webm", "application/octet-stream")
    has_valid_ext = any(filename.endswith(ext) for ext in allowed_exts) or not filename

    if not is_audio_type and not has_valid_ext:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid audio format. Supported formats: WebM, OGG, WAV, MP3, M4A."
        )

    # 3. Save to disk under safe UUID filename (No raw user paths)
    ext = ".webm"
    for candidate in allowed_exts:
        if filename.endswith(candidate):
            ext = candidate
            break

    safe_file_ref = f"voice_{uuid.uuid4().hex}{ext}"
    dest_path = VOICE_STORAGE_DIR / safe_file_ref

    try:
        with open(dest_path, "wb") as f:
            f.write(audio_bytes)
    except Exception as e:
        logger.error(f"Failed to persist voice message: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to save voice file.")

    # 4. Record GuardianMessage
    duration_val = max(0.0, round(float(duration), 1)) if duration is not None else 0.0

    message = GuardianMessage(
        conversation_id=conv.id,
        sender_id=caller_id,
        sender_role=caller_role,
        message_type="VOICE",
        text_content=None,
        voice_file_path=str(dest_path),
        voice_file_reference=safe_file_ref,
        voice_duration=duration_val,
        is_read=False,
        created_at=datetime.now(timezone.utc)
    )
    db.add(message)
    conv.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(message)

    serialized = _serialize_message(message, db)
    broadcast_chat_event(conv.id, {"type": "new_message", "message": serialized})

    return serialized


@router.get(
    "/messages/{message_id}/voice",
    summary="Securely stream a private voice message (Authorized participants only)"
)
def get_voice_audio(
    message_id: int,
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    message = db.query(GuardianMessage).filter(GuardianMessage.id == message_id).first()
    if not message or not message.voice_file_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Voice message not found.")

    conv = db.query(GuardianConversation).filter(GuardianConversation.id == message.conversation_id).first()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found.")

    # Enforce conversation ownership & role check
    _verify_conversation_access(auth_ctx, conv, db)

    file_path = Path(message.voice_file_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Voice audio file missing on server.")

    # Determine media type
    media_type = "audio/webm"
    if file_path.suffix == ".mp3":
        media_type = "audio/mpeg"
    elif file_path.suffix == ".ogg":
        media_type = "audio/ogg"
    elif file_path.suffix == ".wav":
        media_type = "audio/wav"
    elif file_path.suffix in (".m4a", ".mp4"):
        media_type = "audio/mp4"

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=message.voice_file_reference or "voice_message.webm"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. READ STATUS
# ─────────────────────────────────────────────────────────────────────────────

@router.patch(
    "/messages/{message_id}/read",
    summary="Mark specific Guardian message as read"
)
def mark_message_read(
    message_id: int,
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    message = db.query(GuardianMessage).filter(GuardianMessage.id == message_id).first()
    if not message:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")

    conv = db.query(GuardianConversation).filter(GuardianConversation.id == message.conversation_id).first()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found.")

    _verify_conversation_access(auth_ctx, conv, db)

    message.is_read = True
    db.commit()

    return {"message": "Message marked as read", "id": message_id}


# ─────────────────────────────────────────────────────────────────────────────
# 5. GUARDIAN SMS SETTINGS & TEST TRIGGER
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/settings",
    response_model=GuardianSettingsResponse,
    summary="Get Guardian SMS notification preferences"
)
def get_guardian_settings(
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])
    conv = get_or_create_guardian_conversation(db, user_id)
    sms_service = SMSService.get_instance()

    return GuardianSettingsResponse(
        sms_high_risk=conv.sms_high_risk,
        sms_critical=conv.sms_critical,
        sms_suspicious=conv.sms_suspicious,
        guardian_phone=conv.guardian_phone,
        sms_configured=sms_service.is_configured(),
        provider_name=sms_service.get_provider_name()
    )


@router.patch(
    "/settings",
    response_model=GuardianSettingsResponse,
    summary="Update Guardian SMS notification preferences"
)
def update_guardian_settings(
    body: GuardianSettingsUpdateRequest,
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])
    conv = get_or_create_guardian_conversation(db, user_id)

    if body.sms_high_risk is not None:
        conv.sms_high_risk = body.sms_high_risk
    if body.sms_critical is not None:
        conv.sms_critical = body.sms_critical
    if body.sms_suspicious is not None:
        conv.sms_suspicious = body.sms_suspicious
    if body.guardian_phone is not None:
        conv.guardian_phone = body.guardian_phone.strip()

    conv.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(conv)

    sms_service = SMSService.get_instance()

    return GuardianSettingsResponse(
        sms_high_risk=conv.sms_high_risk,
        sms_critical=conv.sms_critical,
        sms_suspicious=conv.sms_suspicious,
        guardian_phone=conv.guardian_phone,
        sms_configured=sms_service.is_configured(),
        provider_name=sms_service.get_provider_name()
    )


@router.post(
    "/send-test-sms",
    summary="Trigger a carrier test SMS to verify Guardian notification channel"
)
def send_test_sms(
    body: Optional[SendTestSMSRequest] = None,
    auth_ctx: dict = Depends(require_role(["user", "guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])
    conv = get_or_create_guardian_conversation(db, user_id)

    phone_number = (body.phone_number if body and body.phone_number else conv.guardian_phone or "").strip()
    sms_service = SMSService.get_instance()

    if not sms_service.is_configured():
        return {
            "status": "not_configured",
            "message": "SMS notifications are not configured."
        }

    if not phone_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No phone number provided or saved in Guardian preferences."
        )

    res = sms_service.send_test_sms(phone_number)
    return res


# ─────────────────────────────────────────────────────────────────────────────
# 6. WEBSOCKET REAL-TIME STREAMING
# ─────────────────────────────────────────────────────────────────────────────

@router.websocket("/ws/{conversation_id}")
async def guardian_chat_websocket(websocket: WebSocket, conversation_id: int):
    """
    WebSocket channel for instant message delivery, voice notes,
    and KAVACH security alerts between User and Guardian.
    """
    await websocket.accept()
    if conversation_id not in _chat_ws_connections:
        _chat_ws_connections[conversation_id] = []
    _chat_ws_connections[conversation_id].append(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            # Echo or broadcast client events to peers
            peers = [ws for ws in _chat_ws_connections.get(conversation_id, []) if ws != websocket]
            for peer in peers:
                try:
                    await peer.send_text(data)
                except Exception:
                    pass
    except WebSocketDisconnect:
        if conversation_id in _chat_ws_connections and websocket in _chat_ws_connections[conversation_id]:
            _chat_ws_connections[conversation_id].remove(websocket)
    except Exception as e:
        logger.warning(f"Guardian Chat WebSocket error: {e}")
        if conversation_id in _chat_ws_connections and websocket in _chat_ws_connections[conversation_id]:
            _chat_ws_connections[conversation_id].remove(websocket)
