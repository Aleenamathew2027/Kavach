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
