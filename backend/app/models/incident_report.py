from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    security_scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("security_scans.id", ondelete="SET NULL"), nullable=True)
    security_alert_id: Mapped[Optional[int]] = mapped_column(ForeignKey("security_alerts.id", ondelete="SET NULL"), nullable=True)

    incident_type: Mapped[str] = mapped_column(String(50), nullable=False)  # SCAM_MESSAGE, PHISHING_LINK, SUSPICIOUS_DOCUMENT, SUSPICIOUS_QR, MULTI_SIGNAL_SCAM
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)     # SAFE, SUSPICIOUS, HIGH RISK, UNSCANNABLE
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="DRAFT", nullable=False)

    sanitized_evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    report_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    user = relationship("User", backref="incident_reports")
    security_scan = relationship("SecurityScan", backref="incident_reports")
    security_alert = relationship("SecurityAlert", backref="incident_reports")

    @property
    def threat_infrastructure(self) -> Dict[str, Any]:
        """
        Retrieves approximate threat infrastructure geolocation details if available.
        Does NOT expose internal DB IDs or claim physical scammer location.
        """
        from sqlalchemy.orm import object_session
        from app.models.threat_location import ThreatLocation

        if not self.security_scan_id:
            return {"available": False}

        session = object_session(self)
        if session is not None:
            loc = session.query(ThreatLocation).filter(
                ThreatLocation.security_scan_id == self.security_scan_id
            ).first()
            if loc and (loc.lookup_status == "SUCCESS" or loc.ip_address):
                return {
                    "available": True,
                    "domain": loc.domain,
                    "ip_address": loc.ip_address,
                    "country": loc.country,
                    "region": loc.region,
                    "city": loc.city,
                    "latitude": loc.latitude,
                    "longitude": loc.longitude,
                    "accuracy_radius": loc.accuracy_radius,
                    "isp": loc.isp,
                    "organization": loc.organization,
                    "asn": loc.asn,
                    "timezone": loc.timezone,
                    "location_source": loc.location_source,
                    "lookup_status": loc.lookup_status,
                }
        elif self.security_scan and getattr(self.security_scan, "threat_locations", None):
            for loc in self.security_scan.threat_locations:
                if loc.lookup_status == "SUCCESS" or loc.ip_address:
                    return {
                        "available": True,
                        "domain": loc.domain,
                        "ip_address": loc.ip_address,
                        "country": loc.country,
                        "region": loc.region,
                        "city": loc.city,
                        "latitude": loc.latitude,
                        "longitude": loc.longitude,
                        "accuracy_radius": loc.accuracy_radius,
                        "isp": loc.isp,
                        "organization": loc.organization,
                        "asn": loc.asn,
                        "timezone": loc.timezone,
                        "location_source": loc.location_source,
                        "lookup_status": loc.lookup_status,
                    }
        return {"available": False}
