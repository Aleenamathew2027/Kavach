import os
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database.base import Base
from app.database.connection import engine, SessionLocal
import app.models.user
import app.models.guardian
import app.models.security_scan
import app.models.security_alert
from app.models.user import User
from app.utils.security import hash_password

load_dotenv()


def init_db():
    """Initialize database tables, ensure schema migrations, and sync predefined admin account."""
    # 1. Apply column addition if not exists (for existing database)
    with engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user' NOT NULL;")
        )

    # 2. Create any missing tables (e.g. guardian_access)
    Base.metadata.create_all(bind=engine)

    # 3. Ensure predefined Administrator account is created/synced
    admin_email = os.getenv("ADMIN_EMAIL", "admin@kavach.com").lower().strip()
    admin_password = os.getenv("ADMIN_PASSWORD", "KavachAdmin@123")

    db: Session = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.email == admin_email).first()
        if not admin_user:
            # Create predefined admin
            new_admin = User(
                full_name="Administrator",
                email=admin_email,
                password=hash_password(admin_password),
                role="admin"
            )
            db.add(new_admin)
            db.commit()
            db.refresh(new_admin)
        else:
            # Ensure role is admin and password matches
            updated = False
            if admin_user.role != "admin":
                admin_user.role = "admin"
                updated = True
            if not admin_user.password.startswith(("$2b$", "$2a$", "$2y$", "$argon2")) or not verify_password(admin_password, admin_user.password):
                admin_user.password = hash_password(admin_password)
                updated = True
            if updated:
                db.commit()

        # 4. Migrate any legacy unhashed user passwords in database to secure bcrypt
        users = db.query(User).all()
        migrated = False
        for u in users:
            if u.password and not u.password.startswith(("$2b$", "$2a$", "$2y$", "$argon2")):
                u.password = hash_password(u.password)
                migrated = True
        if migrated:
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
