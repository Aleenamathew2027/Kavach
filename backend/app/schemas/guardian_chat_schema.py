"""
=============================================================================
KAVACH — Guardian Private Communication System Schemas
=============================================================================
Defines Pydantic request and response contracts for:
  - Private Guardian ↔ User conversations
  - Normal text messaging
  - Recorded voice messages
  - Sanitized KAVACH system alerts
  - Guardian SMS notification preferences
=============================================================================
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SendTextMessageRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000, description="Text message content")


class GuardianMessageResponse(BaseModel):
    id: int
    conversation_id: int
    sender_id: int
    sender_role: str  # 'user', 'guardian', 'system'
    message_type: str  # 'TEXT', 'VOICE', 'SYSTEM_ALERT'
    text_content: Optional[str] = None
    voice_duration: Optional[float] = None
    has_voice: bool = False
    voice_url: Optional[str] = None
    alert_id: Optional[int] = None
    alert_severity: Optional[str] = None
    alert_title: Optional[str] = None
    incident_report_id: Optional[str] = None
    is_read: bool = False
    created_at: str


class GuardianConversationResponse(BaseModel):
    id: int
    user_id: int
    guarded_user: Dict[str, Any]
    is_guardian_linked: bool
    unread_count: int
    sms_high_risk: bool
    sms_critical: bool
    sms_suspicious: bool
    guardian_phone: Optional[str] = None
    created_at: str
    updated_at: str


class GuardianSettingsUpdateRequest(BaseModel):
    sms_high_risk: Optional[bool] = None
    sms_critical: Optional[bool] = None
    sms_suspicious: Optional[bool] = None
    guardian_phone: Optional[str] = None


class GuardianSettingsResponse(BaseModel):
    sms_high_risk: bool
    sms_critical: bool
    sms_suspicious: bool
    guardian_phone: Optional[str] = None
    sms_configured: bool
    provider_name: str


class SendTestSMSRequest(BaseModel):
    phone_number: Optional[str] = None
