"""
=============================================================================
KAVACH — Incident Report Management Service
=============================================================================
Handles creation, unique report ID generation (KAV-YYYY-XXXXXX), DB storage,
privacy-sanitized evidence formatting, user isolation, and PDF generation.
=============================================================================
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.incident_report import IncidentReport
from app.models.security_alert import SecurityAlert
from app.models.security_scan import SecurityScan
from app.models.user import User
from app.services.pdf_report_generator import generate_incident_report_pdf


def generate_unique_report_id(db: Session) -> str:
    """Generates a dynamic unique report ID format: KAV-YYYY-XXXXXX"""
    current_year = datetime.now(timezone.utc).year
    # Count total reports to calculate 6-digit sequence
    total_count = db.query(func.count(IncidentReport.id)).scalar() or 0
    sequence_num = total_count + 1
    return f"KAV-{current_year}-{sequence_num:06d}"


def map_scan_type_to_incident_type(scan_type: str) -> str:
    """Maps security scan types to standard Incident Types."""
    s_type = (scan_type or "").lower().strip()
    if s_type == "message":
        return "SCAM_MESSAGE"
    elif s_type == "link":
        return "PHISHING_LINK"
    elif s_type == "document":
        return "SUSPICIOUS_DOCUMENT"
    elif s_type == "qr":
        return "SUSPICIOUS_QR"
    return "MULTI_SIGNAL_SCAM"


def sanitize_evidence_data(raw_data: Dict[str, Any], scan_type: str, mask_private: bool = False) -> Dict[str, Any]:
    """
    Formulates a privacy-safe evidence dictionary.
    If mask_private=True (for Guardian views), sensitive text snippet strings are masked.
    """
    ref = raw_data.get("input_reference") or raw_data.get("filename") or raw_data.get("url") or "Digital Content"
    summary = raw_data.get("result_summary") or raw_data.get("summary") or "Security incident detected."
    text_preview = raw_data.get("text_preview") or raw_data.get("preview") or ""

    if mask_private and text_preview:
        masked_preview = text_preview[:20] + "... [PRIVATE CONTENT MASKED FOR GUARDIAN PRIVACY]"
    else:
        masked_preview = text_preview

    return {
        "input_reference": ref,
        "summary": summary,
        "scan_type": scan_type,
        "text_preview": masked_preview,
        "detected_indicators": raw_data.get("detected_indicators") or raw_data.get("indicators") or [],
        "masked_for_privacy": mask_private,
    }


def create_incident_report_from_scan(
    db: Session,
    user_id: int,
    scan_id: int,
    custom_title: Optional[str] = None
) -> IncidentReport:
    """Creates a new IncidentReport database record from a SecurityScan."""
    scan = db.query(SecurityScan).filter(
        SecurityScan.id == scan_id,
        SecurityScan.user_id == user_id
    ).first()

    if not scan:
        raise ValueError(f"Security scan #{scan_id} not found for authenticated user.")

    # Check if a report already exists for this scan to avoid duplicates
    existing = db.query(IncidentReport).filter(
        IncidentReport.security_scan_id == scan.id,
        IncidentReport.user_id == user_id
    ).first()
    if existing:
        return existing

    report_id = generate_unique_report_id(db)
    incident_type = map_scan_type_to_incident_type(scan.scan_type)
    
    title = custom_title or f"Cyber Incident Report: {scan.scan_type.capitalize()} Threat"
    sanitized_ev = sanitize_evidence_data(
        raw_data={
            "input_reference": scan.input_reference,
            "result_summary": scan.result_summary,
            "detected_indicators": scan.detected_indicators,
        },
        scan_type=scan.scan_type,
        mask_private=False
    )

    metadata = {
        "scan_id": scan.id,
        "scan_type": scan.scan_type,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "detected_indicators": scan.detected_indicators or [],
    }

    report = IncidentReport(
        report_id=report_id,
        user_id=user_id,
        security_scan_id=scan.id,
        incident_type=incident_type,
        risk_level=scan.risk_level,
        risk_score=scan.risk_score,
        title=title,
        summary=scan.result_summary or f"Flagged {scan.scan_type} security incident.",
        detected_at=scan.created_at or datetime.now(timezone.utc),
        status="DRAFT",
        sanitized_evidence=sanitized_ev,
        report_metadata=metadata
    )

    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_user_incident_reports(db: Session, user_id: int) -> List[IncidentReport]:
    """Retrieves all incident reports owned by user_id."""
    return db.query(IncidentReport).filter(
        IncidentReport.user_id == user_id
    ).order_by(IncidentReport.created_at.desc()).all()


def get_incident_report_by_id(
    db: Session,
    report_id: str,
    requesting_user_id: int,
    role: str = "user"
) -> Optional[IncidentReport]:
    """
    Retrieves an IncidentReport record while enforcing strict RBAC user isolation.
    """
    query = db.query(IncidentReport).filter(IncidentReport.report_id == report_id)
    
    if role.lower() == "user":
        query = query.filter(IncidentReport.user_id == requesting_user_id)
    elif role.lower() == "guardian":
        # Guardian can access report if it belongs to their guarded user_id
        query = query.filter(IncidentReport.user_id == requesting_user_id)
    # Admin can access any report_id without user_id restriction

    return query.first()


def generate_pdf_for_report(
    db: Session,
    report_id: str,
    requesting_user_id: int,
    role: str = "user"
) -> bytes:
    """
    Validates authorization, formats sanitized report data, and generates PDF bytes.
    """
    report = get_incident_report_by_id(db, report_id, requesting_user_id, role)
    if not report:
        raise ValueError("Incident report not found or authorization denied.")

    is_guardian = (role.lower() == "guardian")
    sanitized_ev = sanitize_evidence_data(
        raw_data=report.sanitized_evidence or {},
        scan_type=report.incident_type,
        mask_private=is_guardian
    )

    threat_infra = getattr(report, "threat_infrastructure", None)
    if not threat_infra or not threat_infra.get("available"):
        from app.models.threat_location import ThreatLocation
        if report.security_scan_id:
            loc = db.query(ThreatLocation).filter(
                ThreatLocation.security_scan_id == report.security_scan_id
            ).first()
            if loc and (loc.lookup_status == "SUCCESS" or loc.ip_address):
                threat_infra = {
                    "available": True,
                    "domain": loc.domain,
                    "ip_address": loc.ip_address,
                    "country": loc.country,
                    "region": loc.region,
                    "city": loc.city,
                    "latitude": loc.latitude,
                    "longitude": loc.longitude,
                    "accuracy_radius": loc.accuracy_radius,
                    "isp": loc.isp,
                    "organization": loc.organization,
                    "asn": loc.asn,
                    "timezone": loc.timezone,
                    "location_source": loc.location_source,
                    "lookup_status": loc.lookup_status,
                }
            else:
                threat_infra = {"available": False}
        else:
            threat_infra = {"available": False}

    data_for_pdf = {
        "report_id": report.report_id,
        "incident_type": report.incident_type,
        "risk_level": report.risk_level,
        "risk_score": report.risk_score,
        "detected_at": report.detected_at.isoformat() if report.detected_at else "",
        "security_scan_id": report.security_scan_id,
        "summary": report.summary,
        "sanitized_evidence": sanitized_ev,
        "detected_indicators": report.sanitized_evidence.get("detected_indicators", []),
        "report_metadata": report.report_metadata or {},
        "threat_infrastructure": threat_infra,
        "recommended_action": (
            "1. Do NOT click links or QR codes in this incident.<br/>"
            "2. Do NOT transfer money or share passwords/OTPs.<br/>"
            "3. Use this complaint draft for reference when filing an official report with law enforcement."
        )
    }

    return generate_incident_report_pdf(data_for_pdf, is_guardian_view=is_guardian)
