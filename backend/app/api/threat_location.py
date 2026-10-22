from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.models.security_scan import SecurityScan
from app.models.threat_location import ThreatLocation
from app.schemas.threat_location_schema import ThreatLocationResponse
from app.utils.security import get_db, require_role

router = APIRouter(
    prefix="/security",
    tags=["Threat Geolocation"]
)


@router.get(
    "/threat-locations/{scan_id}",
    response_model=ThreatLocationResponse,
    summary="Get approximate threat infrastructure geolocation for a security scan"
)
def get_threat_locations(
    scan_id: int,
    auth_ctx: Dict[str, Any] = Depends(require_role(["user", "admin", "guardian"])),
    db: Session = Depends(get_db)
):
    """
    Retrieve approximate threat infrastructure geolocation for a specific scan.

    DISCLAIMER:
    IP-based geolocation is approximate and may represent hosting, CDN, VPN,
    proxy, or other network infrastructure rather than the person operating the threat.
    Never interprets this as the physical address of an individual.

    Access Control:
    - User can only access scans belonging to their own account.
    - Guardian can only access scans belonging to their linked protected user.
    - Admin can access any scan.
    """
    scan = db.query(SecurityScan).filter(SecurityScan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security scan with ID {scan_id} not found."
        )

    role = auth_ctx["role"]
    if role == "user":
        current_user = auth_ctx["user"]
        if scan.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access forbidden: you can only view threat locations for your own security scans."
            )
    elif role == "guardian":
        payload = auth_ctx["payload"]
        try:
            guarded_user_id = int(payload.get("sub", -1))
        except (ValueError, TypeError):
            guarded_user_id = -1

        if scan.user_id != guarded_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access forbidden: you can only view threat locations for your protected user."
            )
    elif role == "admin":
        pass  # Admin has full audit access

    locations = db.query(ThreatLocation).filter(
        ThreatLocation.security_scan_id == scan_id
    ).order_by(ThreatLocation.created_at.asc()).all()

    return {
        "scan_id": scan_id,
        "locations": locations,
        "disclaimer": (
            "IP-based geolocation is approximate and may represent hosting, CDN, VPN, "
            "proxy, or other network infrastructure rather than the person operating the threat."
        )
    }
