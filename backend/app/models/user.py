from typing import Optional
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(150), unique=True, index=True, nullable=False)
    password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False)
    auth_provider: Mapped[str] = mapped_column(String(50), default="local", nullable=False)
    google_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True, nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)