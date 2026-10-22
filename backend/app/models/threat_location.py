from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ThreatLocation(Base):
    """
    ThreatLocation model for storing approximate threat infrastructure geolocation.
    
    IMPORTANT:
    IP-based geolocation identifies approximate network/hosting infrastructure,
    NOT the exact physical location of a person or scammer.
    """
    __tablename__ = "threat_locations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    security_scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("security_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    latitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    accuracy_radius: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    isp: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    location_source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    lookup_status: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    # Relationships
    security_scan = relationship("SecurityScan", backref="threat_locations")
