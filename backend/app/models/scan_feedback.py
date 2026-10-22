from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ScanFeedback(Base):
    __tablename__ = "scan_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    security_scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actual_result: Mapped[str] = mapped_column(String(30), nullable=False)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    # Relationships
    user = relationship("User", backref="scan_feedback")
    security_scan = relationship("SecurityScan", backref="scan_feedback")
