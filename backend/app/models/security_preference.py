from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class SecurityPreference(Base):
    __tablename__ = "security_preferences"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_security_preferences_user_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    alert_notifications: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    guardian_notifications: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    high_risk_alerts: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    email_notifications: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    auto_incident_reports: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    user = relationship("User", backref="security_preferences")
