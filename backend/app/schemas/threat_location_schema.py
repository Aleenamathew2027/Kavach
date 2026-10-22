from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class ThreatLocationItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius: Optional[float] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    asn: Optional[str] = None
    timezone: Optional[str] = None
    location_source: Optional[str] = None
    lookup_status: str
    created_at: datetime


class ThreatLocationResponse(BaseModel):
    scan_id: int
    locations: List[ThreatLocationItem]
    disclaimer: str = (
        "IP-based geolocation is approximate and may represent hosting, CDN, VPN, "
        "proxy, or other network infrastructure rather than the person operating the threat."
    )
