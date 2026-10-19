from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.models.guardian import GuardianAccess
from app.models.user import User
from app.schemas.user_schema import (
    GuardianCodeGenerateResponse,
    GuardianCodeVerifyRequest,
    GuardianDashboardResponse,
    Token,
)
from app.utils.security import (
    create_access_token,
    generate_guardian_code,
    get_db,
    hash_password,
    require_role,
    verify_password,
)

router = APIRouter(
    prefix="/guardian",
    tags=["Guardian"]
)


@router.post(
    "/generate-code",
    response_model=GuardianCodeGenerateResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate a 6-digit guardian access code (User only)"
)
def generate_code(
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]

    # Deactivate prior active codes for this user
    db.query(GuardianAccess).filter(
        GuardianAccess.user_id == user.id,
        GuardianAccess.is_active == True
    ).update({"is_active": False, "revoked_at": datetime.now(timezone.utc)})

    # Generate 6-digit numeric code
    raw_code = generate_guardian_code()
    code_hash = hash_password(raw_code)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    guardian_access = GuardianAccess(
        user_id=user.id,
        code_hash=code_hash,
        is_active=True,
        expires_at=expires_at
    )

    db.add(guardian_access)
    db.commit()
    db.refresh(guardian_access)

    return {
        "message": "Guardian access code generated successfully. Share this 6-digit code with your trusted guardian.",
        "code": raw_code,
        "expires_at": expires_at
    }


@router.post(
    "/revoke-code",
    summary="Revoke active guardian access codes (User only)"
)
def revoke_code(
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]

    db.query(GuardianAccess).filter(
        GuardianAccess.user_id == user.id,
        GuardianAccess.is_active == True
    ).update({"is_active": False, "revoked_at": datetime.now(timezone.utc)})
    db.commit()

    return {
        "message": "All guardian access codes have been revoked."
    }


@router.post(
    "/verify-code",
    response_model=Token,
    summary="Verify 6-digit guardian access code and receive guardian JWT"
)
def verify_code(
    body: GuardianCodeVerifyRequest,
    db: Session = Depends(get_db)
):
    now = datetime.now(timezone.utc)

    # Fetch active, unexpired guardian access entries
    active_codes = db.query(GuardianAccess).filter(
        GuardianAccess.is_active == True,
        GuardianAccess.expires_at > now
    ).all()

    matched_access = None
    for access in active_codes:
        if verify_password(body.code, access.code_hash):
            matched_access = access
            break

    if not matched_access:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired guardian access code.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    target_user = db.query(User).filter(User.id == matched_access.user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorized user account not found.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Issue JWT token with guardian role
    access_token = create_access_token(
        data={
            "sub": str(target_user.id),
            "role": "guardian",
            "guardian_access_id": matched_access.id,
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": "guardian",
    }


from app.models.security_alert import SecurityAlert
from app.models.security_scan import SecurityScan


@router.get(
    "/dashboard",
    response_model=GuardianDashboardResponse,
    summary="Guardian dashboard: view authorized user security status"
)
def guardian_dashboard(
    auth_ctx: dict = Depends(require_role(["guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])
    guardian_access_id = payload.get("guardian_access_id")

    # Verify guardian access record is still active
    if guardian_access_id:
        access = db.query(GuardianAccess).filter(
            GuardianAccess.id == guardian_access_id,
            GuardianAccess.is_active == True,
            GuardianAccess.expires_at > datetime.now(timezone.utc)
        ).first()
        if not access:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Guardian authorization has expired or been revoked.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        authorized_until = access.expires_at
    else:
        authorized_until = datetime.now(timezone.utc) + timedelta(hours=24)

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Protected user account not found."
        )

    # Compute live stats from PostgreSQL
    threats_detected = db.query(SecurityScan).filter(
        SecurityScan.user_id == target_user.id,
        SecurityScan.risk_level == "HIGH RISK"
    ).count()

    suspicious_messages = db.query(SecurityScan).filter(
        SecurityScan.user_id == target_user.id,
        SecurityScan.scan_type == "message",
        SecurityScan.risk_level.in_(["SUSPICIOUS", "HIGH RISK"])
    ).count()

    suspicious_links = db.query(SecurityScan).filter(
        SecurityScan.user_id == target_user.id,
        SecurityScan.scan_type == "link",
        SecurityScan.risk_level.in_(["SUSPICIOUS", "HIGH RISK"])
    ).count()

    suspicious_documents = db.query(SecurityScan).filter(
        SecurityScan.user_id == target_user.id,
        SecurityScan.scan_type == "document",
        SecurityScan.risk_level.in_(["SUSPICIOUS", "HIGH RISK"])
    ).count()

    # Fetch sanitized high-level alerts (Strictly no private message text, passwords, or raw files)
    alerts = db.query(SecurityAlert).filter(
        SecurityAlert.user_id == target_user.id
    ).order_by(SecurityAlert.created_at.desc()).limit(10).all()

    recent_alerts = []
    for a in alerts:
        type_label = "Suspicious Message" if "message" in a.alert_type else ("Suspicious Link" if "link" in a.alert_type else "Suspicious Document")
        recent_alerts.append({
            "id": a.id,
            "type": type_label,
            "title": f"High-Risk {type_label} Flagged",
            "severity": a.severity,
            "time": a.created_at.isoformat(),
            "recommended_action": "Please contact the user and make sure they do not respond or make payments."
        })

    overall_status = "ATTENTION REQUIRED" if threats_detected > 0 else "SAFE"
    security_status = "Attention Required - Threat detected" if threats_detected > 0 else "Protected - No active high-risk alerts"

    return {
        "message": "Welcome to Guardian Dashboard",
        "role": "guardian",
        "guarded_user": {
            "id": target_user.id,
            "full_name": target_user.full_name,
            "email": target_user.email,
        },
        "security_status": security_status,
        "overall_status": overall_status,
        "security_summary": {
            "threats_detected": threats_detected,
            "suspicious_messages": suspicious_messages,
            "suspicious_links": suspicious_links,
            "suspicious_documents": suspicious_documents,
        },
        "recent_alerts": recent_alerts,
        "protection_modules": [
            "AI Scam & Phishing Detection",
            "Deepfake Voice Call Analyzer",
            "Malicious URL & Document Scanner",
            "Suspicious Transaction Alerts"
        ],
        "authorized_until": authorized_until
    }


@router.get(
    "/alerts",
    summary="Get all security alerts for the guarded user (Guardian only)"
)
def get_guardian_alerts(
    auth_ctx: dict = Depends(require_role(["guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])

    alerts = db.query(SecurityAlert).filter(
        SecurityAlert.user_id == user_id
    ).order_by(SecurityAlert.created_at.desc()).all()

    res = []
    for a in alerts:
        type_label = "Suspicious Message" if "message" in a.alert_type else ("Suspicious Link" if "link" in a.alert_type else "Suspicious Document")
        res.append({
            "id": a.id,
            "alert_type": a.alert_type,
            "threat_type": type_label,
            "title": a.title,
            "message": a.message,
            "severity": a.severity,
            "is_read": a.is_read,
            "time": a.created_at.isoformat(),
            "created_at": a.created_at.isoformat(),
            "recommended_action": "Verify with the user and advise them not to click links, share OTPs, or approve payments."
        })
    return res


@router.patch(
    "/alerts/{alert_id}/read",
    summary="Mark guarded user's alert as read by Guardian"
)
def mark_guardian_alert_read(
    alert_id: int,
    auth_ctx: dict = Depends(require_role(["guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])

    alert = db.query(SecurityAlert).filter(
        SecurityAlert.id == alert_id,
        SecurityAlert.user_id == user_id
    ).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    alert.is_read = True
    db.commit()
    return {"message": "Alert marked as read", "id": alert_id}


@router.get(
    "/activity",
    summary="Get privacy-safe security activity log for guarded user (Guardian only)"
)
def get_guardian_activity(
    auth_ctx: dict = Depends(require_role(["guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    user_id = int(payload["sub"])

    scans = db.query(SecurityScan).filter(
        SecurityScan.user_id == user_id
    ).order_by(SecurityScan.created_at.desc()).limit(30).all()

    items = []
    for s in scans:
        items.append({
            "id": f"scan-{s.id}",
            "type": s.scan_type,
            "event": f"{s.scan_type.capitalize()} Safety Check",
            "risk_level": s.risk_level,
            "risk_score": s.risk_score,
            "summary": s.result_summary,
            "time": s.created_at.isoformat() if s.created_at else None,
        })
    return items


from app.services.incident_report_service import generate_pdf_for_report, get_incident_report_by_id
from app.models.incident_report import IncidentReport
from app.schemas.incident_report_schema import IncidentReportResponse
from fastapi import Response
from typing import List

@router.get(
    "/reports",
    response_model=List[IncidentReportResponse],
    summary="List privacy-safe incident report summaries for the guarded user (Guardian only)"
)
def list_guardian_reports(
    auth_ctx: dict = Depends(require_role(["guardian"])),
    db: Session = Depends(get_db)
):
    """
    Returns all incident reports belonging to the Guardian's linked user.
    Authorization is enforced via the Guardian JWT (sub = guarded user_id).
    Does NOT return raw evidence — only safe summary fields.
    """
    payload = auth_ctx["payload"]
    guarded_user_id = int(payload["sub"])

    reports = db.query(IncidentReport).filter(
        IncidentReport.user_id == guarded_user_id
    ).order_by(IncidentReport.created_at.desc()).all()

    return reports


@router.get(
    "/reports/{report_id}",
    response_model=IncidentReportResponse,
    summary="Get a specific incident report summary for the guarded user (Guardian only)"
)
def get_guardian_report_detail(
    report_id: str,
    auth_ctx: dict = Depends(require_role(["guardian"])),
    db: Session = Depends(get_db)
):
    """
    Returns a single incident report for the guarded user.
    Guardian can only access reports belonging to their linked user.
    """
    payload = auth_ctx["payload"]
    guarded_user_id = int(payload["sub"])

    report = get_incident_report_by_id(
        db=db,
        report_id=report_id,
        requesting_user_id=guarded_user_id,
        role="guardian"
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident report not found or access denied."
        )
    return report


@router.get(
    "/reports/{report_id}/download",
    summary="Download privacy-sanitized incident report draft for guarded user (Guardian only)"
)
def download_guardian_report_pdf(
    report_id: str,
    auth_ctx: dict = Depends(require_role(["guardian"])),
    db: Session = Depends(get_db)
):
    payload = auth_ctx["payload"]
    guarded_user_id = int(payload["sub"])
    try:
        pdf_bytes = generate_pdf_for_report(
            db=db,
            report_id=report_id,
            requesting_user_id=guarded_user_id,
            role="guardian"
        )
        filename = f"KAVACH_Guardian_Report_{report_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(val_err)
        )


