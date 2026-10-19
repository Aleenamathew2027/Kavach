from typing import List
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.incident_report_schema import (
    IncidentReportGenerateRequest,
    IncidentReportResponse,
)
from app.services.incident_report_service import (
    create_incident_report_from_scan,
    generate_pdf_for_report,
    get_incident_report_by_id,
    get_user_incident_reports,
)
from app.utils.security import get_db, require_role

router = APIRouter(
    prefix="/security/reports",
    tags=["Incident Reports & Complaint Drafts"]
)


@router.post(
    "/generate",
    response_model=IncidentReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a Cyber Security Incident Report / Complaint Draft from a scan (User only)"
)
def generate_report(
    body: IncidentReportGenerateRequest,
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    try:
        report = create_incident_report_from_scan(
            db=db,
            user_id=user.id,
            scan_id=body.security_scan_id,
            custom_title=body.title
        )
        return report
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )


@router.get(
    "",
    response_model=List[IncidentReportResponse],
    summary="List all incident report complaint drafts for authenticated user"
)
def list_reports(
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    return get_user_incident_reports(db, user.id)


@router.get(
    "/{report_id}",
    response_model=IncidentReportResponse,
    summary="Get details of a specific incident report complaint draft (User only)"
)
def get_report_details(
    report_id: str,
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    report = get_incident_report_by_id(db, report_id=report_id, requesting_user_id=user.id, role="user")
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident report not found or access denied."
        )
    return report


@router.get(
    "/{report_id}/download",
    summary="Download incident report / complaint draft as a PDF document"
)
def download_report_pdf(
    report_id: str,
    auth_ctx: dict = Depends(require_role(["user"])),
    db: Session = Depends(get_db)
):
    user: User = auth_ctx["user"]
    try:
        pdf_bytes = generate_pdf_for_report(
            db=db,
            report_id=report_id,
            requesting_user_id=user.id,
            role="user"
        )
        filename = f"Cyber_Incident_Report_{report_id}.pdf"
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
