"""
=============================================================================
KAVACH — Guardian Private Communication System Database Models
=============================================================================
Defines relational models for:
  - GuardianConversation: Represents the secure 1-to-1 link between a
    Protected User and their verified Guardian.
  - GuardianMessage: Normal text messages, recorded voice messages,
    and sanitized KAVACH security alert system notifications.
=============================================================================
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class GuardianConversation(Base):
    __tablename__ = "guardian_conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    guardian_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)

    # SMS & Notification Preferences for this Guardian channel
    sms_high_risk: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sms_critical: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sms_suspicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    guardian_phone: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user = relationship("User", backref="guardian_conversation", foreign_keys=[user_id])
    messages = relationship(
        "GuardianMessage",
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="GuardianMessage.created_at.asc()"
    )


class GuardianMessage(Base):
    __tablename__ = "guardian_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("guardian_conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    sender_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    sender_role: Mapped[str] = mapped_column(String(20), nullable=False)  # 'user', 'guardian', 'system'
    message_type: Mapped[str] = mapped_column(String(20), nullable=False, default="TEXT")  # 'TEXT', 'VOICE', 'SYSTEM_ALERT'

    # Text message content or sanitized alert message
    text_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Voice message metadata (file stored securely on server disk, not raw BLOB in DB)
    voice_file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    voice_file_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    voice_duration: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # Duration in seconds

    # Link to security alert if this message was generated from a KAVACH threat event
    alert_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("security_alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    # Relationships
    conversation = relationship("GuardianConversation", back_populates="messages")
    security_alert = relationship("SecurityAlert", backref="chat_messages", foreign_keys=[alert_id])
