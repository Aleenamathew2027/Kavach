import os
import sys
from pathlib import Path

# Ensure root backend directory is in sys.path when executed directly as a script
backend_root = str(Path(__file__).resolve().parent.parent.parent)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database.base import Base
from app.database.connection import engine, SessionLocal
import app.models.user
import app.models.guardian
import app.models.security_scan
import app.models.security_alert
import app.models.incident_report
import app.models.ai_conversation
import app.models.ai_message
import app.models.user_feedback
import app.models.security_action
import app.models.security_preference
import app.models.scan_feedback
import app.models.threat_location
import app.models.guardian_chat
from app.models.user import User
from app.utils.security import hash_password, verify_password

load_dotenv()


def init_db():
    """Initialize database tables, ensure schema migrations, and sync predefined admin account."""
    # 1. Create any missing tables (e.g. users, guardian_access, security_scans, security_alerts, threat_locations)
    Base.metadata.create_all(bind=engine)

    # 2. Apply column additions and constraints idempotently for existing legacy databases
    try:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user' NOT NULL;")
            )
            conn.execute(
                text("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(50) DEFAULT 'local' NOT NULL;")
            )
            conn.execute(
                text("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255);")
            )
            conn.execute(
                text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500);")
            )
            conn.execute(
                text("ALTER TABLE users ALTER COLUMN password DROP NOT NULL;")
            )
    except Exception:
        # Ignore errors if columns already exist or if dialect doesn't support ALTER
        pass

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
                role="admin",
                auth_provider="local"
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
            if not admin_user.password or not admin_user.password.startswith(("$2b$", "$2a$", "$2y$", "$argon2")) or not verify_password(admin_password, admin_user.password):
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


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
