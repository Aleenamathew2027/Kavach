from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.models.security_alert import SecurityAlert
from app.models.security_scan import SecurityScan
from app.models.user import User
from app.schemas.security_schema import (
    DocumentAnalyzeResponse,
    LinkAnalyzeRequest,
    LinkAnalyzeResponse,
    MessageAnalyzeRequest,
    MessageAnalyzeResponse,
    SecurityAlertResponse,
    SecuritySummaryResponse,
)
from app.services.document_scanner import analyze_document_content
from app.services.link_scanner import analyze_link_url
from app.services.message_scanner import analyze_message_text
from app.utils.security import get_db, require_role

router = APIRouter(
    prefix="/security",
    tags=["Security Scans & Alerts"]
)


@router.post(
    "/analyze-message",
    response_model=MessageAnalyzeResponse,
    summary="Analyze suspicious message for scam indicators"
)
def analyze_message(
    body: MessageAnalyzeRequest,
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    result = analyze_message_text(body.message)

    # Safe truncated reference (not full private message text)
    clean_preview = body.message.strip().replace("\n", " ")
    ref = clean_preview[:60] + ("…" if len(clean_preview) > 60 else "")

    scan = SecurityScan(
        user_id=user.id,
        scan_type="message",
        input_reference=ref,
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        detected_indicators=result["detected_indicators"],
        result_summary=result["summary"],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    alert_created = False
    if result["risk_level"] == "HIGH RISK":
        indicator_str = ", ".join(result["detected_indicators"][:2]) if result["detected_indicators"] else "Scam patterns"
        alert = SecurityAlert(
            user_id=user.id,
            alert_type="message_scam",
            title="High-Risk Scam Message Detected",
            message=f"Kavach detected high-risk scam indicators: {indicator_str}.",
            severity="HIGH",
            is_read=False
        )
        db.add(alert)
        db.commit()
        alert_created = True

    return {
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "detected_indicators": result["detected_indicators"],
        "reasons": result["reasons"],
        "recommended_action": result["recommended_action"],
        "summary": result["summary"],
        "scan_id": scan.id,
        "alert_created": alert_created,
    }


@router.post(
    "/analyze-link",
    response_model=LinkAnalyzeResponse,
    summary="Inspect suspicious link or URL for phishing/malware"
)
def analyze_link(
    body: LinkAnalyzeRequest,
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    result = analyze_link_url(body.url)

    ref = body.url.strip()[:80]

    scan = SecurityScan(
        user_id=user.id,
        scan_type="link",
        input_reference=ref,
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        detected_indicators=result["detected_indicators"],
        result_summary=result["summary"],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    alert_created = False
    if result["risk_level"] == "HIGH RISK":
        indicator_str = ", ".join(result["detected_indicators"][:2]) if result["detected_indicators"] else "Suspicious domain"
        alert = SecurityAlert(
            user_id=user.id,
            alert_type="link_scam",
            title="High-Risk Malicious Link Detected",
            message=f"Kavach flagged suspicious URL ({ref}): {indicator_str}.",
            severity="HIGH",
            is_read=False
        )
        db.add(alert)
        db.commit()
        alert_created = True

    return {
        "url": result["url"],
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "detected_indicators": result["detected_indicators"],
        "reasons": result["reasons"],
        "recommended_action": result["recommended_action"],
        "summary": result["summary"],
        "scan_id": scan.id,
        "alert_created": alert_created,
    }


@router.post(
    "/analyze-document",
    response_model=DocumentAnalyzeResponse,
    summary="Safely extract and analyze document for scam indicators"
)
async def analyze_document(
    file: UploadFile = File(...),
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]

    # Read uploaded bytes with size validation
    contents = await file.read()
    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds maximum allowable limit of 10MB."
        )

    result = analyze_document_content(contents, file.filename or "uploaded_document")

    scan = SecurityScan(
        user_id=user.id,
        scan_type="document",
        input_reference=file.filename[:80] if file.filename else "Document",
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        detected_indicators=result["detected_indicators"],
        result_summary=result["summary"],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    alert_created = False
    if result["risk_level"] == "HIGH RISK":
        indicator_str = ", ".join(result["detected_indicators"][:2]) if result["detected_indicators"] else "Fraudulent content"
        alert = SecurityAlert(
            user_id=user.id,
            alert_type="document_scam",
            title=f"High-Risk Scam Document Detected: {file.filename}",
            message=f"Document contains high-risk scam indicators: {indicator_str}.",
            severity="HIGH",
            is_read=False
        )
        db.add(alert)
        db.commit()
        alert_created = True

    return {
        "filename": result["filename"],
        "file_type": result["file_type"],
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "detected_indicators": result["detected_indicators"],
        "reasons": result["reasons"],
        "text_preview": result["text_preview"],
        "recommended_action": result["recommended_action"],
        "summary": result["summary"],
        "scan_id": scan.id,
        "alert_created": alert_created,
    }


@router.get(
    "/alerts",
    response_model=List[SecurityAlertResponse],
    summary="Get user security alerts list"
)
def get_user_alerts(
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    alerts = db.query(SecurityAlert).filter(
        SecurityAlert.user_id == user.id
    ).order_by(SecurityAlert.created_at.desc()).all()

    return alerts


@router.patch(
    "/alerts/{alert_id}/read",
    summary="Mark an alert as read"
)
def mark_alert_read(
    alert_id: int,
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    alert = db.query(SecurityAlert).filter(
        SecurityAlert.id == alert_id,
        SecurityAlert.user_id == user.id
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
    "/summary",
    response_model=SecuritySummaryResponse,
    summary="Get authenticated user's real security metrics from PostgreSQL"
)
def get_security_summary(
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]

    threats_detected = db.query(SecurityScan).filter(
        SecurityScan.user_id == user.id,
        SecurityScan.risk_level == "HIGH RISK"
    ).count()

    suspicious_messages = db.query(SecurityScan).filter(
        SecurityScan.user_id == user.id,
        SecurityScan.scan_type == "message",
        SecurityScan.risk_level.in_(["SUSPICIOUS", "HIGH RISK"])
    ).count()

    suspicious_links = db.query(SecurityScan).filter(
        SecurityScan.user_id == user.id,
        SecurityScan.scan_type == "link",
        SecurityScan.risk_level.in_(["SUSPICIOUS", "HIGH RISK"])
    ).count()

    suspicious_documents = db.query(SecurityScan).filter(
        SecurityScan.user_id == user.id,
        SecurityScan.scan_type == "document",
        SecurityScan.risk_level.in_(["SUSPICIOUS", "HIGH RISK"])
    ).count()

    total_scans = db.query(SecurityScan).filter(
        SecurityScan.user_id == user.id
    ).count()

    # Active threat level: HIGH if any high risk alert or scan in last 24h else LOW
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_high_risks = db.query(SecurityScan).filter(
        SecurityScan.user_id == user.id,
        SecurityScan.risk_level == "HIGH RISK",
        SecurityScan.created_at >= since_24h
    ).count()

    active_threat_level = "HIGH" if recent_high_risks > 0 else "LOW"

    return {
        "threats_detected": threats_detected,
        "suspicious_messages": suspicious_messages,
        "suspicious_links": suspicious_links,
        "suspicious_documents": suspicious_documents,
        "total_scans": total_scans,
        "active_threat_level": active_threat_level,
    }
