from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    full_name: Mapped[str] = mapped_column(String(100))

    email: Mapped[str] = mapped_column(String(150), unique=True)

    password: Mapped[str] = mapped_column(String(255))