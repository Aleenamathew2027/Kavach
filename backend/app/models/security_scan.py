from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class SecurityScan(Base):
    __tablename__ = "security_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # 'message', 'link', 'document'
    input_reference: Mapped[str] = mapped_column(String(255), nullable=False)  # Truncated preview / domain / filename
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # 'SAFE', 'SUSPICIOUS', 'HIGH RISK'
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0 to 100
    detected_indicators: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    user = relationship("User", backref="security_scans")
