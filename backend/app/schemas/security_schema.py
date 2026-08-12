from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MessageAnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="Message text to analyze for scam patterns")


class MessageAnalyzeResponse(BaseModel):
    risk_level: str
    risk_score: int
    detected_indicators: List[str]
    reasons: List[str]
    recommended_action: str
    summary: str
    scan_id: Optional[int] = None
    alert_created: bool = False


class LinkAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL or link address to inspect")


class LinkAnalyzeResponse(BaseModel):
    url: str
    risk_level: str
    risk_score: int
    detected_indicators: List[str]
    reasons: List[str]
    recommended_action: str
    summary: str
    scan_id: Optional[int] = None
    alert_created: bool = False


class DocumentAnalyzeResponse(BaseModel):
    filename: str
    file_type: str
    risk_level: str
    risk_score: int
    detected_indicators: List[str]
    reasons: List[str]
    text_preview: str
    recommended_action: str
    summary: str
    scan_id: Optional[int] = None
    alert_created: bool = False


class SecurityAlertResponse(BaseModel):
    id: int
    alert_type: str
    title: str
    message: str
    severity: str
    is_read: bool
    created_at: datetime


class SecuritySummaryResponse(BaseModel):
    threats_detected: int
    suspicious_messages: int
    suspicious_links: int
    suspicious_documents: int
    total_scans: int
    active_threat_level: str
