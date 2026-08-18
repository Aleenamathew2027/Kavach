from datetime import datetime, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.models.guardian import GuardianAccess
from app.models.security_alert import SecurityAlert
from app.models.security_scan import SecurityScan
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
    summary="Admin SOC Dashboard Metrics (Administrator only)"
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

    total_scans = db.query(SecurityScan).count()
    threats_detected = db.query(SecurityScan).filter(SecurityScan.risk_level == "HIGH RISK").count()
    suspicious_incidents = db.query(SecurityScan).filter(SecurityScan.risk_level == "SUSPICIOUS").count()
    safe_scans = db.query(SecurityScan).filter(SecurityScan.risk_level == "SAFE").count()

    # Scans by category
    msg_scans = db.query(SecurityScan).filter(SecurityScan.scan_type == "message").count()
    link_scans = db.query(SecurityScan).filter(SecurityScan.scan_type == "link").count()
    doc_scans = db.query(SecurityScan).filter(SecurityScan.scan_type == "document").count()

    # Recent scans
    recent_scans = db.query(SecurityScan).order_by(SecurityScan.created_at.desc()).limit(8).all()
    recent_list = [
        {
            "id": s.id,
            "user_id": s.user_id,
            "scan_type": s.scan_type,
            "input_reference": s.input_reference,
            "risk_level": s.risk_level,
            "risk_score": s.risk_score,
            "summary": s.result_summary,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in recent_scans
    ]

    return {
        "message": "Welcome to KAVACH SOC Admin Dashboard",
        "admin_email": admin_user.email,
        "role": "admin",
        "total_users": total_users,
        "active_guardian_links": active_guardians,
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "suspicious_incidents": suspicious_incidents,
        "safe_scans": safe_scans,
        "scans_by_type": {
            "message": msg_scans,
            "link": link_scans,
            "document": doc_scans,
        },
        "recent_scans": recent_list,
        "system_status": "All KAVACH Security Services Operational",
    }


@router.get(
    "/admin/users",
    summary="Get all registered users with security metrics (Administrator only)"
)
def get_admin_users(
    auth_ctx: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    res = []
    for u in users:
        scans_count = db.query(SecurityScan).filter(SecurityScan.user_id == u.id).count()
        threats_count = db.query(SecurityScan).filter(
            SecurityScan.user_id == u.id,
            SecurityScan.risk_level == "HIGH RISK"
        ).count()
        res.append({
            "id": u.id,
            "full_name": u.full_name,
            "email": u.email,
            "role": u.role.upper(),
            "status": "ACTIVE",
            "created_at": "12 Aug 2026",
            "total_scans": scans_count,
            "threats_detected": threats_count,
        })
    return res


@router.get(
    "/admin/security-events",
    summary="Get all system security scan events (Administrator only)"
)
def get_admin_security_events(
    auth_ctx: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    scans = db.query(SecurityScan).order_by(SecurityScan.created_at.desc()).limit(100).all()
    events = []
    for s in scans:
        user = db.query(User).filter(User.id == s.user_id).first()
        user_name = user.full_name if user else f"User #{s.user_id}"
        user_email = user.email if user else "—"

        events.append({
            "id": s.id,
            "user_id": s.user_id,
            "user_name": user_name,
            "user_email": user_email,
            "scan_type": s.scan_type,
            "input_reference": s.input_reference,
            "risk_level": s.risk_level,
            "risk_score": s.risk_score,
            "detected_indicators": s.detected_indicators or [],
            "summary": s.result_summary,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "status": "FLAGGED" if s.risk_level == "HIGH RISK" else ("SUSPICIOUS" if s.risk_level == "SUSPICIOUS" else "VERIFIED SAFE"),
        })
    return events


@router.get(
    "/admin/guardians",
    summary="Get all Guardian Access linkages (Administrator only)"
)
def get_admin_guardians(
    auth_ctx: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    now = datetime.now(timezone.utc)
    access_records = db.query(GuardianAccess).order_by(GuardianAccess.created_at.desc()).all()
    res = []
    for a in access_records:
        user = db.query(User).filter(User.id == a.user_id).first()
        status_label = "ACTIVE" if (a.is_active and a.expires_at > now) else ("REVOKED" if a.revoked_at else "EXPIRED")
        res.append({
            "id": a.id,
            "user_id": a.user_id,
            "user_name": user.full_name if user else f"User #{a.user_id}",
            "user_email": user.email if user else "—",
            "is_active": a.is_active,
            "status": status_label,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "expires_at": a.expires_at.isoformat() if a.expires_at else None,
            "relationship": "Trusted Family Guardian",
        })
    return res


@router.get(
    "/admin/reports",
    summary="Get aggregate security analytics & trends (Administrator only)"
)
def get_admin_reports(
    auth_ctx: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    total_users = db.query(User).count()
    total_scans = db.query(SecurityScan).count()
    threats_detected = db.query(SecurityScan).filter(SecurityScan.risk_level == "HIGH RISK").count()
    suspicious = db.query(SecurityScan).filter(SecurityScan.risk_level == "SUSPICIOUS").count()
    safe = db.query(SecurityScan).filter(SecurityScan.risk_level == "SAFE").count()

    msg_threats = db.query(SecurityScan).filter(SecurityScan.scan_type == "message", SecurityScan.risk_level == "HIGH RISK").count()
    link_threats = db.query(SecurityScan).filter(SecurityScan.scan_type == "link", SecurityScan.risk_level == "HIGH RISK").count()
    doc_threats = db.query(SecurityScan).filter(SecurityScan.scan_type == "document", SecurityScan.risk_level == "HIGH RISK").count()

    safe_rate = round((safe / total_scans * 100), 1) if total_scans > 0 else 100.0

    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "safety_rate": safe_rate,
        "threats_by_type": {
            "message": msg_threats,
            "link": link_threats,
            "document": doc_threats,
        },
        "scans_by_type": {
            "message": db.query(SecurityScan).filter(SecurityScan.scan_type == "message").count(),
            "link": db.query(SecurityScan).filter(SecurityScan.scan_type == "link").count(),
            "document": db.query(SecurityScan).filter(SecurityScan.scan_type == "document").count(),
        },
        "active_guardians": db.query(GuardianAccess).filter(GuardianAccess.is_active == True, GuardianAccess.expires_at > datetime.now(timezone.utc)).count(),
    }


@router.get(
    "/admin/activity",
    summary="Get chronological system activity audit log (Administrator only)"
)
def get_admin_activity(
    auth_ctx: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    scans = db.query(SecurityScan).order_by(SecurityScan.created_at.desc()).limit(50).all()
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(50).all()

    items = []
    for s in scans:
        u = db.query(User).filter(User.id == s.user_id).first()
        items.append({
            "id": f"scan-{s.id}",
            "type": "SECURITY_SCAN",
            "title": f"Security {s.scan_type.capitalize()} Scan Completed",
            "detail": f"{u.full_name if u else 'User'} analyzed {s.input_reference} ({s.risk_level})",
            "severity": s.risk_level,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })

    for a in alerts:
        u = db.query(User).filter(User.id == a.user_id).first()
        items.append({
            "id": f"alert-{a.id}",
            "type": "SECURITY_ALERT",
            "title": a.title,
            "detail": f"{u.full_name if u else 'User'}: {a.message}",
            "severity": a.severity,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })

    # Sort descending by timestamp
    items.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return items[:50]


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
