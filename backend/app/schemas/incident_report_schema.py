from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class IncidentReportGenerateRequest(BaseModel):
    security_scan_id: int
    title: Optional[str] = None


class IncidentReportResponse(BaseModel):
    id: int
    report_id: str
    user_id: int
    security_scan_id: Optional[int] = None
    security_alert_id: Optional[int] = None
    incident_type: str
    risk_level: str
    risk_score: int
    title: str
    summary: str
    detected_at: datetime
    created_at: datetime
    status: str
    sanitized_evidence: Dict[str, Any]
    report_metadata: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)
