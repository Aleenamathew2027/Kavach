from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class SecurityAction(Base):
    __tablename__ = "security_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    security_alert_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("security_alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    security_scan_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("security_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    action_status: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    # Relationships
    user = relationship("User", backref="security_actions")
    security_alert = relationship("SecurityAlert", backref="security_actions")
    security_scan = relationship("SecurityScan", backref="security_actions")
