"""
Threat Infrastructure Geolocation Service for KAVACH (Phase 18A).

IMPORTANT DISCLAIMER:
IP-based geolocation identifies approximate network/hosting infrastructure,
NOT the exact physical location of a person or scammer.
It represents hosting providers, CDNs, VPNs, proxies, or telecommunication gateways.
"""

import ipaddress
import logging
import os
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.security_scan import SecurityScan
from app.models.threat_location import ThreatLocation

logger = logging.getLogger("kavach.services.threat_geolocation")

DISCLAIMER_TEXT = (
    "IP-based geolocation is approximate and represents hosting, CDN, VPN, "
    "proxy, or network infrastructure rather than the physical location of the attacker."
)

RESERVED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
]


class GeoLocationProvider:
    """Abstract base class for IP geolocation providers."""

    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Query provider for approximate network infrastructure geolocation.
        Must return a dictionary containing location attributes and 'status'.
        """
        raise NotImplementedError


class IPApiProvider(GeoLocationProvider):
    """
    Concrete geolocation provider using ip-api.com.
    Supports optional GEOLOCATION_API_KEY environment variable for Pro endpoints.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEOLOCATION_API_KEY", "").strip()

    def lookup(self, ip: str) -> Dict[str, Any]:
        fields = "status,message,country,regionName,city,lat,lon,isp,org,as,timezone"
        if self.api_key:
            url = f"https://pro.ip-api.com/json/{ip}?key={self.api_key}&fields={fields}"
        else:
            url = f"http://ip-api.com/json/{ip}?fields={fields}"

        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(url)
                if response.status_code != 200:
                    logger.warning(f"Geolocation provider returned HTTP {response.status_code} for IP {ip}")
                    return {
                        "status": "LOOKUP_FAILED",
                        "location_source": "ip-api",
                    }

                data = response.json()
                if data.get("status") == "success":
                    return {
                        "status": "SUCCESS",
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "latitude": float(data["lat"]) if data.get("lat") is not None else None,
                        "longitude": float(data["lon"]) if data.get("lon") is not None else None,
                        "accuracy_radius": None,  # ip-api does not provide accuracy radius; explicitly store None
                        "isp": data.get("isp"),
                        "organization": data.get("org"),
                        "asn": data.get("as"),
                        "timezone": data.get("timezone"),
                        "location_source": "ip-api",
                    }
                else:
                    msg = str(data.get("message", "")).lower()
                    if "not found" in msg or "invalid" in msg:
                        status = "NOT_FOUND"
                    elif "private" in msg or "reserved" in msg:
                        status = "PRIVATE_IP"
                    else:
                        status = "LOOKUP_FAILED"
                    return {
                        "status": status,
                        "location_source": "ip-api",
                    }
        except Exception as e:
            logger.error(f"Geolocation provider error for IP {ip}: {e}")
            return {
                "status": "LOOKUP_FAILED",
                "location_source": "ip-api",
            }


_active_provider: GeoLocationProvider = IPApiProvider()


def get_geolocation_provider() -> GeoLocationProvider:
    """Get the active geolocation provider instance."""
    return _active_provider


def set_geolocation_provider(provider: GeoLocationProvider) -> None:
    """Set custom or mocked geolocation provider for testing or alternative providers."""
    global _active_provider
    _active_provider = provider


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Safely extract domain/hostname from a suspicious URL without making HTTP requests.
    Handles http, https, ports, and paths.
    """
    if not url or not isinstance(url, str):
        return None

    raw = url.strip()
    if not raw:
        return None

    # Ensure a scheme is present so urlparse correctly parses netloc
    if "://" not in raw:
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
        hostname = parsed.hostname
        if not hostname:
            # Fallback if hostname is None
            netloc = parsed.netloc.split(":")[0].strip()
            hostname = netloc if netloc else None

        if hostname:
            hostname = hostname.lower().strip()
            # Remove any trailing dot from FQDN
            if hostname.endswith("."):
                hostname = hostname[:-1]
            return hostname if hostname else None
        return None
    except Exception as e:
        logger.debug(f"Failed to parse URL '{url}': {e}")
        return None


def is_public_ip(ip: str) -> bool:
    """
    Validate whether an IP string is a public, routable IP address.
    Strictly rejects loopback, RFC1918 private, link-local, multicast,
    unspecified, CGNAT (100.64.0.0/10), and 0.0.0.0/8 ranges.
    """
    if not ip or not isinstance(ip, str):
        return False

    clean_ip = ip.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)

        if (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return False

        if any(ip_obj in net for net in RESERVED_NETWORKS):
            return False

        if ip_obj.version == 6 and (ip_obj.is_private or ip_obj.is_reserved):
            return False

        return True
    except ValueError:
        return False


def resolve_domain_to_ips(domain: str) -> List[str]:
    """
    Resolve domain name to IPv4 addresses using DNS standard library.
    Never makes an HTTP request to the target domain.
    Returns a sorted list of unique IP addresses.
    """
    if not domain or not isinstance(domain, str):
        return []

    clean_domain = domain.strip().lower()
    if clean_domain in {"localhost", "127.0.0.1", "::1"}:
        return ["127.0.0.1"]

    # If domain is already an IP literal
    try:
        ip_obj = ipaddress.ip_address(clean_domain)
        return [str(ip_obj)]
    except ValueError:
        pass

    ips: List[str] = []
    try:
        results = socket.getaddrinfo(clean_domain, None, socket.AF_INET, socket.SOCK_STREAM)
        for res in results:
            ip_str = res[4][0]
            if ip_str not in ips:
                ips.append(ip_str)
    except (socket.gaierror, socket.herror, OSError) as e:
        logger.debug(f"DNS resolution failed for '{clean_domain}': {e}")

    return sorted(ips)


def geolocate_ip(ip: str) -> Dict[str, Any]:
    """
    Perform geolocation lookup for a single IP address.
    Validates public IP status before querying provider.
    """
    if not ip or not isinstance(ip, str):
        return {
            "status": "INVALID_IP",
            "ip_address": ip,
            "location_source": "none",
        }

    clean_ip = ip.strip()
    try:
        ipaddress.ip_address(clean_ip)
    except ValueError:
        return {
            "status": "INVALID_IP",
            "ip_address": clean_ip,
            "location_source": "none",
        }

    if not is_public_ip(clean_ip):
        return {
            "status": "PRIVATE_IP",
            "ip_address": clean_ip,
            "location_source": "internal",
        }

    provider = get_geolocation_provider()
    result = provider.lookup(clean_ip)
    result["ip_address"] = clean_ip
    return result


def analyze_threat_infrastructure(url: str) -> Dict[str, Any]:
    """
    Analyze approximate threat infrastructure for a given URL:
    1. Extract domain
    2. Resolve DNS to public IPs
    3. Look up approximate network geolocation
    Never makes HTTP requests to the target domain.
    """
    domain = extract_domain_from_url(url)
    if not domain:
        return {
            "status": "INVALID_IP",
            "domain": None,
            "ip_address": None,
            "location": None,
        }

    resolved_ips = resolve_domain_to_ips(domain)
    if not resolved_ips:
        return {
            "status": "NOT_FOUND",
            "domain": domain,
            "ip_address": None,
            "location": None,
        }

    # Filter for public IPs
    public_ips = [ip for ip in resolved_ips if is_public_ip(ip)]
    if not public_ips:
        # All resolved IPs are private/loopback/reserved
        private_ip = resolved_ips[0]
        return {
            "status": "PRIVATE_IP",
            "domain": domain,
            "ip_address": private_ip,
            "location": None,
        }

    chosen_ip = public_ips[0]
    geo_data = geolocate_ip(chosen_ip)

    return {
        "status": geo_data.get("status", "SUCCESS"),
        "domain": domain,
        "ip_address": chosen_ip,
        "location": geo_data,
    }


def create_threat_location_for_scan(
    db: Session,
    security_scan: SecurityScan,
    suspicious_url: str
) -> Optional[ThreatLocation]:
    """
    Safely resolve, geolocate, and store threat infrastructure for a security scan.
    Duplicate protection ensures rows are not duplicated for the same scan and IP/domain.
    Geolocation failure NEVER causes an exception or invalidates the security scan.
    """
    try:
        analysis = analyze_threat_infrastructure(suspicious_url)
        domain = analysis.get("domain")
        ip_addr = analysis.get("ip_address")
        status = analysis.get("status", "LOOKUP_FAILED")
        loc_data = analysis.get("location") or {}

        # Duplicate protection
        existing = db.query(ThreatLocation).filter(
            ThreatLocation.security_scan_id == security_scan.id,
            ThreatLocation.domain == domain,
            ThreatLocation.ip_address == ip_addr,
        ).first()

        if existing:
            return existing

        threat_loc = ThreatLocation(
            security_scan_id=security_scan.id,
            domain=domain,
            ip_address=ip_addr,
            country=loc_data.get("country"),
            region=loc_data.get("region"),
            city=loc_data.get("city"),
            latitude=loc_data.get("latitude"),
            longitude=loc_data.get("longitude"),
            accuracy_radius=loc_data.get("accuracy_radius"),
            isp=loc_data.get("isp"),
            organization=loc_data.get("organization"),
            asn=loc_data.get("asn"),
            timezone=loc_data.get("timezone"),
            location_source=loc_data.get("location_source"),
            lookup_status=status,
        )

        db.add(threat_loc)
        db.commit()
        db.refresh(threat_loc)
        return threat_loc

    except Exception as e:
        logger.error(f"Error creating threat location for scan #{security_scan.id}: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return None


def get_threat_locations_for_scan(db: Session, scan_id: int) -> List[Dict[str, Any]]:
    """
    Retrieve formatted threat infrastructure geolocation records for a scan ID.
    Ready for integration into Incident Reports (Phase 18C).
    """
    locations = db.query(ThreatLocation).filter(
        ThreatLocation.security_scan_id == scan_id
    ).order_by(ThreatLocation.created_at.asc()).all()

    return [
        {
            "id": loc.id,
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
            "created_at": loc.created_at.isoformat() if loc.created_at else None,
        }
        for loc in locations
    ]
