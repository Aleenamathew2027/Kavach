from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class IncidentReportGenerateRequest(BaseModel):
    security_scan_id: int
    title: Optional[str] = None


class ThreatInfrastructureSummary(BaseModel):
    available: bool = False
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius: Optional[float] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    asn: Optional[str] = None
    timezone: Optional[str] = None
    location_source: Optional[str] = None
    lookup_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


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
    threat_infrastructure: Optional[ThreatInfrastructureSummary] = None

    model_config = ConfigDict(from_attributes=True)
