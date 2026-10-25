"""
=============================================================================
KAVACH — Live Voice Guardian API Router
=============================================================================
Provides real-time endpoints for:
  - Two-person call session creation & joining
  - Audio chunk Speech-To-Text (English, Malayalam, Mixed)
  - Real-time Vishing / Voice Scam Risk Analysis
  - Advisory warning generation & sanitized Guardian alerts
  - WebRTC signaling & WebSocket real-time event distribution
=============================================================================
"""

import base64
import json
import logging
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
from sqlalchemy.orm import Session

from app.models.security_alert import SecurityAlert
from app.models.security_scan import SecurityScan
from app.models.user import User
from app.schemas.live_voice_schema import (
    VoiceAnalyzeRequest,
    VoiceAnalyzeResponse,
    VoiceSessionCreateRequest,
    VoiceSessionCreateResponse,
    VoiceSessionDetailResponse,
    VoiceSessionEndRequest,
    VoiceSessionEndResponse,
    VoiceSessionJoinRequest,
    VoiceSessionJoinResponse,
    VoiceSignalRequest,
    VoiceTranscribeRequest,
    VoiceTranscribeResponse,
)
from app.services.incident_report_service import create_incident_report_from_scan
from app.services.live_voice_risk_service import LiveVoiceRiskService
from app.services.live_voice_session_manager import LiveVoiceSessionManager
from app.services.live_voice_stt_service import LiveVoiceSTTService
from app.utils.security import get_db, require_role, decode_access_token

logger = logging.getLogger("kavach.api.live_voice")

router = APIRouter(
    prefix="/voice",
    tags=["Live Voice Guardian"]
)

# Active WebSocket connections grouped by session_id
_ws_connections: Dict[str, List[WebSocket]] = {}


@router.post(
    "/session/create",
    response_model=VoiceSessionCreateResponse,
    summary="Create a new 2-person Live Voice Guardian call session"
)
def create_voice_session(
    body: Optional[VoiceSessionCreateRequest] = None,
    auth_ctx: dict = Depends(require_role(["user"])),
):
    user: User = auth_ctx["user"]
    custom_code = body.room_code if body else None

    session_mgr = LiveVoiceSessionManager.get_instance()
    session = session_mgr.create_session(
        host_id=user.id,
        host_name=user.full_name or f"User {user.id}",
        room_code=custom_code
    )

    return VoiceSessionCreateResponse(
        session_id=session.session_id,
        room_code=session.room_code,
        status=session.status,
        created_at=session.created_at.isoformat(),
        message="Voice call session created. Share the Room Code with the second participant to join.",
        your_role="Participant 1",
    )


@router.post(
    "/session/join",
    response_model=VoiceSessionJoinResponse,
    summary="Join an existing Live Voice Guardian call session (Max 2 Participants)"
)
def join_voice_session(
    body: VoiceSessionJoinRequest,
    auth_ctx: dict = Depends(require_role(["user"])),
):
    user: User = auth_ctx["user"]
    session_key = (body.room_code or body.session_id or "").strip()
    if not session_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either room_code or session_id must be provided to join a call."
        )

    session_mgr = LiveVoiceSessionManager.get_instance()
    success, message, session = session_mgr.join_session(
        session_id_or_code=session_key,
        user_id=user.id,
        user_name=user.full_name or f"User {user.id}"
    )

    if not success or not session:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    return VoiceSessionJoinResponse(
        session_id=session.session_id,
        room_code=session.room_code,
        status=session.status,
        participant_count=len(session.participants),
        participants=list(session.participants.values()),
        message=message,
        your_role="Participant 2",
    )


@router.get(
    "/session/{session_id}",
    response_model=VoiceSessionDetailResponse,
    summary="Retrieve live voice session state and current telemetry"
)
def get_voice_session(
    session_id: str,
    auth_ctx: dict = Depends(require_role(["user"])),
):
    session = LiveVoiceSessionManager.get_instance().get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Voice call session not found or expired."
        )

    return VoiceSessionDetailResponse(**session.to_dict())


@router.post(
    "/session/signal/{session_id}",
    summary="Exchange WebRTC SDP offers, answers, and ICE candidates between peers"
)
def send_voice_signal(
    session_id: str,
    body: VoiceSignalRequest,
    auth_ctx: dict = Depends(require_role(["user"])),
):
    user: User = auth_ctx["user"]
    session_mgr = LiveVoiceSessionManager.get_instance()
    enqueued = session_mgr.add_signal(
        session_id=session_id,
        sender_id=user.id,
        signal_payload={
            "type": body.type,
            "payload": body.payload,
            "target_id": body.target_id,
        }
    )
    if not enqueued:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to forward WebRTC signal. Session may be inactive or ended."
        )
    return {"status": "success", "message": "Signal queued for peer."}


@router.get(
    "/session/signals/{session_id}",
    summary="Retrieve pending WebRTC signals intended for the current user"
)
def get_voice_signals(
    session_id: str,
    auth_ctx: dict = Depends(require_role(["user"])),
):
    user: User = auth_ctx["user"]
    session_mgr = LiveVoiceSessionManager.get_instance()
    signals = session_mgr.get_pending_signals(session_id=session_id, user_id=user.id)
    return {"signals": signals}


@router.post(
    "/transcribe",
    response_model=VoiceTranscribeResponse,
    summary="Transcribe audio chunk (English, Malayalam, or Mixed speech)"
)
async def transcribe_voice_chunk(
    body: Optional[VoiceTranscribeRequest] = None,
    audio_file: Optional[UploadFile] = File(None),
    language: Optional[str] = Form(None),
    auth_ctx: dict = Depends(require_role(["user"])),
):
    """
    Accepts either multipart audio upload or JSON base64 chunk.
    Routes to LiveVoiceSTTService clean abstraction.
    """
    raw_bytes = b""
    req_language = language

    if audio_file:
        raw_bytes = await audio_file.read()
    elif body and body.audio_base64:
        try:
            # Strip potential data URL prefix
            data_str = body.audio_base64
            if "," in data_str:
                data_str = data_str.split(",", 1)[1]
            raw_bytes = base64.b64decode(data_str)
            req_language = body.language or req_language
        except Exception as e:
            logger.warning(f"Failed to decode base64 audio chunk: {e}")
            raw_bytes = b""

    stt_service = LiveVoiceSTTService.get_instance()
    result = stt_service.transcribe_audio(raw_bytes, language=req_language)

    return VoiceTranscribeResponse(
        text=result.get("text", ""),
        language=result.get("language", req_language or "en"),
        confidence=result.get("confidence", 0.0),
        provider=result.get("provider", "builtin"),
        error=result.get("error"),
    )


@router.post(
    "/analyze",
    response_model=VoiceAnalyzeResponse,
    summary="Analyze live speech transcript for vishing and voice scam indicators"
)
def analyze_voice(
    body: VoiceAnalyzeRequest,
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    """
    Analyzes live speech chunk. Supports English, Malayalam script, and Manglish.
    Produces 0-100 risk score and triggers advisory warning.
    If HIGH RISK, records a sanitized SecurityScan and notifies Guardian without
    leaking the private conversation text.
    """
    user: User = auth_ctx["user"]
    session_mgr = LiveVoiceSessionManager.get_instance()
    session = session_mgr.get_session(body.session_id) if body.session_id else None

    # Retrieve turn history if session exists
    context_turns = session.transcripts if session else None

    risk_analysis = LiveVoiceRiskService.analyze_transcript(
        text=body.text,
        speaker=body.speaker,
        language=body.language,
        context_history=context_turns
    )

    risk_level = risk_analysis["risk_level"]
    risk_score = risk_analysis["risk_score"]
    detected_indicators = risk_analysis["detected_indicators"]
    reasons = risk_analysis["reasons"]
    rec_action = risk_analysis["recommended_action"]
    summary = risk_analysis["summary"]
    detected_lang = risk_analysis["detected_language"]

    # Record in active session history if session active
    if session:
        session_mgr.record_transcript_and_risk(
            session_id=session.session_id,
            speaker_id=user.id,
            speaker_name=body.speaker or user.full_name or f"User {user.id}",
            text=body.text,
            language=detected_lang,
            risk_result=risk_analysis
        )

    guardian_alert_sent = False
    report_id = None

    # Handle HIGH RISK: Privacy-preserving Guardian integration and optional Incident Report
    if risk_level == "HIGH RISK" and body.sync_guardian:
        try:
            # 1. Record sanitized SecurityScan
            sanitized_ref = f"[Voice Call] Vishing Indicators: {', '.join(detected_indicators[:2])}"
            scan = SecurityScan(
                user_id=user.id,
                scan_type="voice",
                input_reference=sanitized_ref[:255],
                risk_level="HIGH RISK",
                risk_score=risk_score,
                detected_indicators=detected_indicators,
                result_summary=f"KAVACH Live Voice Guardian flagged potential voice scam: {', '.join(detected_indicators)}.",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            # 2. Emit Sanitized Security Alert for User & Guardian (NO private transcript text)
            indicator_summary = ", ".join(detected_indicators[:2]) if detected_indicators else "Vishing Pattern"
            alert = SecurityAlert(
                user_id=user.id,
                alert_type="voice_vishing_scam",
                title="🔴 High-Risk Voice Scam Detected",
                message=f"Live Voice Guardian detected high-risk scam activity during active call: {indicator_summary}. Do not share OTP, PIN, or credentials.",
                severity="HIGH",
                is_read=False,
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            guardian_alert_sent = True

            # 3. Create Incident Report from Scan (consistent with existing system)
            try:
                inc_report = create_incident_report_from_scan(
                    db=db,
                    user_id=user.id,
                    scan_id=scan.id,
                    custom_title="Cyber Security Incident Report: Real-Time Voice Scam (Vishing)"
                )
                if alert:
                    inc_report.security_alert_id = alert.id
                    db.commit()
                report_id = inc_report.report_id
            except Exception as rep_err:
                logger.error(f"Failed to automatically generate incident report for voice scan #{scan.id}: {rep_err}")

            # Deliver sanitized alert to Guardian Chat & SMS
            if alert:
                try:
                    from app.services.guardian_notification_service import handle_security_alert_notification
                    handle_security_alert_notification(db, alert)
                except Exception as notif_err:
                    logger.error(f"Failed to dispatch Guardian chat alert for voice: {notif_err}")

        except Exception as e:
            logger.error(f"Failed to record voice security alert: {e}", exc_info=True)

    return VoiceAnalyzeResponse(
        risk_level=risk_level,
        risk_score=risk_score,
        detected_indicators=detected_indicators,
        reasons=reasons,
        recommended_action=rec_action,
        summary=summary,
        detected_language=detected_lang,
        guardian_alert_sent=guardian_alert_sent,
        incident_report_id=report_id,
    )


@router.post(
    "/session/end",
    response_model=VoiceSessionEndResponse,
    summary="End an active Live Voice Guardian call session"
)
def end_voice_session(
    body: VoiceSessionEndRequest,
    auth_ctx: dict = Depends(require_role(["user"])),
):
    user: User = auth_ctx["user"]
    session_mgr = LiveVoiceSessionManager.get_instance()
    success, msg, session = session_mgr.end_session(
        session_id=body.session_id,
        ended_by_user_id=user.id
    )

    if not success or not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already closed."
        )

    duration = 0
    if session.ended_at and session.created_at:
        duration = int((session.ended_at - session.created_at).total_seconds())

    return VoiceSessionEndResponse(
        session_id=session.session_id,
        status="ENDED",
        peak_risk_level=session.peak_risk_level,
        peak_risk_score=session.peak_risk_score,
        duration_seconds=max(0, duration),
        message="Voice call session ended successfully."
    )


@router.websocket("/ws/{session_id}")
async def voice_websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for bidirectional real-time WebRTC signaling,
    transcript synchronization, and live risk broadcasting between the 2 callers.
    """
    await websocket.accept()
    if session_id not in _ws_connections:
        _ws_connections[session_id] = []
    _ws_connections[session_id].append(websocket)

    # Notify existing peers that a peer joined
    existing_peers = [ws for ws in _ws_connections.get(session_id, []) if ws != websocket]
    for peer in existing_peers:
        try:
            await peer.send_text(json.dumps({
                "type": "peer_joined",
                "participant_count": len(_ws_connections[session_id])
            }))
        except Exception:
            pass

    # Notify the connecting peer if another peer is already present
    if len(existing_peers) > 0:
        try:
            await websocket.send_text(json.dumps({
                "type": "peer_waiting",
                "participant_count": len(_ws_connections[session_id])
            }))
        except Exception:
            pass

    try:
        while True:
            raw_data = await websocket.receive_text()
            try:
                msg = json.loads(raw_data)
            except Exception:
                continue

            # Forward signaling, transcripts, risk alerts, and peer coordination events to other peers
            peers = [ws for ws in _ws_connections.get(session_id, []) if ws != websocket]
            for peer in peers:
                try:
                    await peer.send_text(raw_data)
                except Exception:
                    pass

    except WebSocketDisconnect:
        if session_id in _ws_connections and websocket in _ws_connections[session_id]:
            _ws_connections[session_id].remove(websocket)
            # Notify remaining peer about departure
            for peer in _ws_connections.get(session_id, []):
                try:
                    await peer.send_text(json.dumps({"type": "peer_disconnected"}))
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"Voice WebSocket error: {e}")
        if session_id in _ws_connections and websocket in _ws_connections[session_id]:
            _ws_connections[session_id].remove(websocket)
