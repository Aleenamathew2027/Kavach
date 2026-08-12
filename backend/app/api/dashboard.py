from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.models.guardian import GuardianAccess
from app.models.user import User
from app.schemas.user_schema import (
    AdminDashboardResponse,
    UserDashboardResponse,
    UserResponse,
)
from app.utils.security import get_db, require_role

router = APIRouter(
    tags=["Dashboards"]
)


@router.get(
    "/admin/dashboard",
    response_model=AdminDashboardResponse,
    summary="Admin Dashboard (Administrator only)"
)
def admin_dashboard(
    auth_ctx: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    admin_user: User = auth_ctx["user"]
    total_users = db.query(User).count()
    active_guardians = db.query(GuardianAccess).filter(
        GuardianAccess.is_active == True,
        GuardianAccess.expires_at > datetime.now(timezone.utc)
    ).count()

    return {
        "message": "Welcome to Admin Dashboard",
        "admin_email": admin_user.email,
        "role": "admin",
        "total_users": total_users,
        "active_guardian_links": active_guardians,
        "system_status": "All KAVACH Security Services Operational"
    }


@router.get(
    "/admin/users",
    summary="Get all registered users for Admin Management (Administrator only)"
)
def get_admin_users(
    auth_ctx: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "full_name": u.full_name,
            "email": u.email,
            "role": u.role.upper(),
            "status": "ACTIVE",
            "created_at": "12 Aug 2026",
            "threats_detected": 0,
            "suspicious_messages": 0,
            "suspicious_calls": 0,
            "suspicious_links": 0,
        }
        for u in users
    ]


@router.get(
    "/user/dashboard",
    response_model=UserDashboardResponse,
    summary="User Dashboard (Standard user only)"
)
def user_dashboard(
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    current_user: User = auth_ctx["user"]
    active_guardian_codes = db.query(GuardianAccess).filter(
        GuardianAccess.user_id == current_user.id,
        GuardianAccess.is_active == True,
        GuardianAccess.expires_at > datetime.now(timezone.utc)
    ).count()

    return {
        "message": "Welcome to User Dashboard",
        "user": UserResponse.model_validate(current_user),
        "security_status": "System Active - Guarding Digital Channels",
        "active_threat_level": "LOW",
        "active_guardian_codes": active_guardian_codes
    }
