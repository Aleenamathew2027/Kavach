"""
=============================================================================
KAVACH — Live Voice Guardian Pydantic Schemas
=============================================================================
Defines validation and response contracts for voice sessions, live STT,
real-time vishing risk analysis, and WebRTC signaling.
=============================================================================
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class VoiceSessionCreateRequest(BaseModel):
    room_code: Optional[str] = Field(None, description="Optional custom room code. If omitted, auto-generated.")


class VoiceSessionCreateResponse(BaseModel):
    session_id: str
    room_code: str
    status: str
    created_at: str
    message: str
    your_role: Optional[str] = "Participant 1"


class VoiceSessionJoinRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Session UUID or room code (e.g. KV-8492)")
    room_code: Optional[str] = Field(None, description="Room code if joining by code")


class VoiceSessionJoinResponse(BaseModel):
    session_id: str
    room_code: str
    status: str
    participant_count: int
    participants: List[Dict[str, Any]]
    message: str
    your_role: Optional[str] = "Participant 2"


class VoiceTranscribeRequest(BaseModel):
    audio_base64: Optional[str] = Field(None, description="Base64 encoded audio chunk data")
    language: Optional[str] = Field(None, description="Language hint: 'en', 'ml', 'mixed', or auto")


class VoiceTranscribeResponse(BaseModel):
    text: str
    language: str
    confidence: float
    provider: str
    error: Optional[str] = None


class VoiceAnalyzeRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional active voice session ID")
    text: str = Field(..., min_length=1, description="Spoken transcript utterance")
    speaker: Optional[str] = Field("Participant", description="Speaker display identifier")
    language: Optional[str] = Field(None, description="Language hint: 'en', 'ml', or 'mixed'")
    sync_guardian: Optional[bool] = Field(True, description="Whether to trigger Guardian alert on HIGH RISK")


class VoiceAnalyzeResponse(BaseModel):
    risk_level: str
    risk_score: int
    detected_indicators: List[str]
    reasons: List[str]
    recommended_action: str
    summary: str
    detected_language: str
    guardian_alert_sent: bool = False
    incident_report_id: Optional[str] = None


class VoiceSignalRequest(BaseModel):
    target_id: Optional[int] = Field(None, description="Specific recipient user ID, or broadcast to peer")
    type: str = Field(..., description="Signal type: 'offer', 'answer', 'candidate', 'ping'")
    payload: Dict[str, Any] = Field(..., description="SDP or ICE candidate payload")


class VoiceSessionEndRequest(BaseModel):
    session_id: str


class VoiceSessionEndResponse(BaseModel):
    session_id: str
    status: str
    peak_risk_level: str
    peak_risk_score: int
    duration_seconds: int
    message: str


class VoiceSessionDetailResponse(BaseModel):
    session_id: str
    room_code: str
    status: str
    participant_count: int
    participants: List[Dict[str, Any]]
    duration_seconds: int
    peak_risk_level: str
    peak_risk_score: int
    latest_risk: Dict[str, Any]
    transcript_count: int
    created_at: str
