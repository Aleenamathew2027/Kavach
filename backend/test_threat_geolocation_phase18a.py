"""
=============================================================================
KAVACH Phase 18A — Threat Infrastructure Geolocation & Backend Tests
=============================================================================
Tests:
  1. Valid domain extraction
  2. URL with path/query extraction
  3. Domain with port
  4. Invalid URL handling
  5. Private IP rejection
  6. Localhost rejection
  7. Loopback rejection
  8. Public IP accepted
  9. Mocked successful geolocation
  10. Mocked provider failure
  11. Database ThreatLocation creation
  12. Duplicate prevention
  13. User cannot access another user's scan location (403)
  14. Admin access works
  15. Guardian access only works for linked protected user
  16. SAFE link does not trigger automatic geolocation
  17. HIGH_RISK link attempts geolocation
  18. Geolocation failure does not fail link scanning
  19. No fake coordinates are generated
  20. accuracy_radius is preserved when provider supplies it
  21. NULL accuracy_radius is accepted when provider does not supply it
=============================================================================
"""

import os
import sys
import pytest
import secrets
from datetime import datetime, timezone
from typing import Any, Dict
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.database.init_db import init_db
from app.models.user import User
from app.models.security_scan import SecurityScan
from app.models.threat_location import ThreatLocation
from app.models.guardian import GuardianAccess
from app.services.threat_geolocation_service import (
    GeoLocationProvider,
    extract_domain_from_url,
    is_public_ip,
    resolve_domain_to_ips,
    geolocate_ip,
    analyze_threat_infrastructure,
    create_threat_location_for_scan,
    set_geolocation_provider,
    get_geolocation_provider,
    IPApiProvider,
)
from app.utils.security import create_access_token

client = TestClient(app)


class MockSuccessProvider(GeoLocationProvider):
    """Mock provider returning structured public infrastructure data."""
    def __init__(self, accuracy_radius=None):
        self.accuracy_radius = accuracy_radius

    def lookup(self, ip: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "country": "United States",
            "region": "California",
            "city": "San Jose",
            "latitude": 37.3382,
            "longitude": -121.8863,
            "accuracy_radius": self.accuracy_radius,
            "isp": "Malicious Cloud VPS LLC",
            "organization": "Bulletproof Hosting Services",
            "asn": "AS65530",
            "timezone": "America/Los_Angeles",
            "location_source": "mock-provider",
        }


class MockFailureProvider(GeoLocationProvider):
    """Mock provider simulating provider timeout or service failure."""
    def lookup(self, ip: str) -> Dict[str, Any]:
        return {
            "status": "LOOKUP_FAILED",
            "location_source": "mock-provider",
        }


class TestThreatGeolocationPhase18A:

    @classmethod
    def setup_class(cls):
        init_db()

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self):
        self.db = SessionLocal()
        self.original_provider = get_geolocation_provider()
        yield
        set_geolocation_provider(self.original_provider)
        self.db.close()

    # 1. Valid domain extraction
    def test_01_valid_domain_extraction(self):
        url = "https://phishing-portal.com"
        assert extract_domain_from_url(url) == "phishing-portal.com"

        url2 = "http://evil-banking.net"
        assert extract_domain_from_url(url2) == "evil-banking.net"

    # 2. URL with path/query extraction
    def test_02_url_with_path_and_query_extraction(self):
        url = "https://secure-login.suspicious.org/auth/login.php?user=admin&token=123#fragment"
        assert extract_domain_from_url(url) == "secure-login.suspicious.org"

        no_scheme = "malicious-site.co.uk/path/index.html"
        assert extract_domain_from_url(no_scheme) == "malicious-site.co.uk"

    # 3. Domain with port
    def test_03_domain_with_port(self):
        url = "http://phishing-host.xyz:8080/portal"
        assert extract_domain_from_url(url) == "phishing-host.xyz"

        url2 = "evil-domain.com:443/login"
        assert extract_domain_from_url(url2) == "evil-domain.com"

    # 4. Invalid URL
    def test_04_invalid_url_handling(self):
        assert extract_domain_from_url("") is None
        assert extract_domain_from_url(None) is None
        assert extract_domain_from_url("   ") is None
        assert extract_domain_from_url("::::") is None

    # 5. Private IP rejection
    def test_05_private_ip_rejection(self):
        private_ips = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.168.0.254",
            "100.64.0.1",       # CGNAT
            "169.254.1.1",      # Link-local
            "0.0.0.0",
        ]
        for ip in private_ips:
            assert is_public_ip(ip) is False, f"Expected {ip} to be rejected as private!"

    # 6. Localhost rejection
    def test_06_localhost_rejection(self):
        assert is_public_ip("localhost") is False
        assert is_public_ip("127.0.0.1") is False
        assert is_public_ip("127.1.2.3") is False

    # 7. Loopback rejection
    def test_07_loopback_rejection(self):
        assert is_public_ip("127.0.0.1") is False
        assert is_public_ip("::1") is False
        assert is_public_ip("fe80::1") is False

    # 8. Public IP accepted
    def test_08_public_ip_accepted(self):
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "142.250.190.46",
            "203.0.113.10",
        ]
        for ip in public_ips:
            assert is_public_ip(ip) is True, f"Expected {ip} to be accepted as public!"

    # 9. Mocked successful geolocation
    def test_09_mocked_successful_geolocation(self):
        set_geolocation_provider(MockSuccessProvider(accuracy_radius=25.0))
        res = geolocate_ip("93.184.216.34")
        assert res["status"] == "SUCCESS"
        assert res["country"] == "United States"
        assert res["city"] == "San Jose"
        assert res["latitude"] == 37.3382
        assert res["longitude"] == -121.8863
        assert res["accuracy_radius"] == 25.0
        assert res["isp"] == "Malicious Cloud VPS LLC"
        assert res["asn"] == "AS65530"

    # 10. Mocked provider failure
    def test_10_mocked_provider_failure(self):
        set_geolocation_provider(MockFailureProvider())
        res = geolocate_ip("93.184.216.34")
        assert res["status"] == "LOOKUP_FAILED"
        assert res.get("country") is None
        assert res.get("latitude") is None

    # 11. Database ThreatLocation creation
    def test_11_database_threat_location_creation(self):
        set_geolocation_provider(MockSuccessProvider(accuracy_radius=10.0))
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"Geo Test User {test_id}",
            email=f"geouser_{test_id}@kavach.ai",
            role="user",
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        scan = SecurityScan(
            user_id=user.id,
            scan_type="link",
            input_reference="https://phishing-domain-test.xyz",
            risk_level="HIGH RISK",
            risk_score=95,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        # Directly invoke service
        threat_loc = create_threat_location_for_scan(
            db=self.db,
            security_scan=scan,
            suspicious_url="https://93.184.216.34/login"
        )
        assert threat_loc is not None
        assert threat_loc.security_scan_id == scan.id
        assert threat_loc.ip_address == "93.184.216.34"
        assert threat_loc.lookup_status == "SUCCESS"
        assert threat_loc.country == "United States"
        assert threat_loc.latitude == 37.3382
        assert threat_loc.accuracy_radius == 10.0

    # 12. Duplicate prevention
    def test_12_duplicate_prevention(self):
        set_geolocation_provider(MockSuccessProvider())
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"Dup User {test_id}",
            email=f"dup_{test_id}@kavach.ai",
            role="user",
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        scan = SecurityScan(
            user_id=user.id,
            scan_type="link",
            input_reference="https://93.184.216.34",
            risk_level="HIGH RISK",
            risk_score=90,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        loc1 = create_threat_location_for_scan(self.db, scan, "https://93.184.216.34")
        count_before = self.db.query(ThreatLocation).filter(
            ThreatLocation.security_scan_id == scan.id
        ).count()

        loc2 = create_threat_location_for_scan(self.db, scan, "https://93.184.216.34")
        count_after = self.db.query(ThreatLocation).filter(
            ThreatLocation.security_scan_id == scan.id
        ).count()

        assert count_before == 1
        assert count_after == 1
        assert loc1.id == loc2.id

    # 13. User cannot access another user's scan location (403)
    def test_13_user_cannot_access_other_users_location(self):
        test_id = secrets.token_hex(4)
        victim = User(full_name=f"Victim {test_id}", email=f"victim_{test_id}@kavach.ai", role="user")
        attacker = User(full_name=f"Attacker {test_id}", email=f"attacker_{test_id}@kavach.ai", role="user")
        self.db.add_all([victim, attacker])
        self.db.commit()
        self.db.refresh(victim)
        self.db.refresh(attacker)

        scan = SecurityScan(user_id=victim.id, scan_type="link", input_reference="http://test.com", risk_level="HIGH RISK", risk_score=90)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        threat_loc = ThreatLocation(security_scan_id=scan.id, domain="test.com", lookup_status="SUCCESS")
        self.db.add(threat_loc)
        self.db.commit()

        # Attacker attempts to access victim's scan locations
        attacker_token = create_access_token({"sub": str(attacker.id), "role": "user"})
        res = client.get(
            f"/security/threat-locations/{scan.id}",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res.status_code == 403, f"Expected 403, got {res.status_code}: {res.text}"

    # 14. Admin access works
    def test_14_admin_access_works(self):
        test_id = secrets.token_hex(4)
        user = User(full_name=f"Normal {test_id}", email=f"normal_{test_id}@kavach.ai", role="user")
        admin = User(full_name=f"Admin {test_id}", email=f"admin_{test_id}@kavach.ai", role="admin")
        self.db.add_all([user, admin])
        self.db.commit()
        self.db.refresh(user)
        self.db.refresh(admin)

        scan = SecurityScan(user_id=user.id, scan_type="link", input_reference="http://test.com", risk_level="HIGH RISK", risk_score=90)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        threat_loc = ThreatLocation(security_scan_id=scan.id, domain="test.com", lookup_status="SUCCESS", country="Japan")
        self.db.add(threat_loc)
        self.db.commit()

        admin_token = create_access_token({"sub": str(admin.id), "role": "admin"})
        res = client.get(
            f"/security/threat-locations/{scan.id}",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
        data = res.json()
        assert data["scan_id"] == scan.id
        assert len(data["locations"]) == 1
        assert data["locations"][0]["country"] == "Japan"

    # 15. Guardian access only works for linked protected user
    def test_15_guardian_access_only_works_for_linked_protected_user(self):
        test_id = secrets.token_hex(4)
        user_protected = User(full_name=f"Protected {test_id}", email=f"protected_{test_id}@kavach.ai", role="user")
        user_unrelated = User(full_name=f"Unrelated {test_id}", email=f"unrelated_{test_id}@kavach.ai", role="user")
        self.db.add_all([user_protected, user_unrelated])
        self.db.commit()
        self.db.refresh(user_protected)
        self.db.refresh(user_unrelated)

        scan_protected = SecurityScan(user_id=user_protected.id, scan_type="link", input_reference="http://p.com", risk_level="HIGH RISK", risk_score=85)
        scan_unrelated = SecurityScan(user_id=user_unrelated.id, scan_type="link", input_reference="http://u.com", risk_level="HIGH RISK", risk_score=85)
        self.db.add_all([scan_protected, scan_unrelated])
        self.db.commit()
        self.db.refresh(scan_protected)
        self.db.refresh(scan_unrelated)

        loc_prot = ThreatLocation(security_scan_id=scan_protected.id, domain="p.com", lookup_status="SUCCESS", country="Germany")
        loc_unrel = ThreatLocation(security_scan_id=scan_unrelated.id, domain="u.com", lookup_status="SUCCESS", country="France")
        self.db.add_all([loc_prot, loc_unrel])
        self.db.commit()

        # Guardian authorized for user_protected
        guardian_token = create_access_token({
            "sub": str(user_protected.id),
            "role": "guardian",
            "guardian_access_id": 9999,
        })
        headers = {"Authorization": f"Bearer {guardian_token}"}

        # Access to protected user's scan -> 200
        res_ok = client.get(f"/security/threat-locations/{scan_protected.id}", headers=headers)
        assert res_ok.status_code == 200
        assert res_ok.json()["locations"][0]["country"] == "Germany"

        # Access to unrelated user's scan -> 403 Forbidden
        res_forbidden = client.get(f"/security/threat-locations/{scan_unrelated.id}", headers=headers)
        assert res_forbidden.status_code == 403

    # 16. SAFE link does not trigger automatic geolocation
    def test_16_safe_link_does_not_trigger_geolocation(self):
        set_geolocation_provider(MockSuccessProvider())
        test_id = secrets.token_hex(4)
        user = User(full_name=f"Safe User {test_id}", email=f"safe_{test_id}@kavach.ai", role="user")
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        user_token = create_access_token({"sub": str(user.id), "role": "user"})
        res = client.post(
            "/security/analyze-link",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"url": "https://www.google.com"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["verdict"] == "SAFE"

        # Threat location should NOT be created for SAFE link
        scan_id = data["scan_id"]
        locations = self.db.query(ThreatLocation).filter(
            ThreatLocation.security_scan_id == scan_id
        ).all()
        assert len(locations) == 0

    # 17. HIGH_RISK link attempts geolocation
    def test_17_high_risk_link_attempts_geolocation(self):
        set_geolocation_provider(MockSuccessProvider(accuracy_radius=50.0))
        test_id = secrets.token_hex(4)
        user = User(full_name=f"Phish User {test_id}", email=f"phish_{test_id}@kavach.ai", role="user")
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        user_token = create_access_token({"sub": str(user.id), "role": "user"})
        # URL designed to trigger HIGH RISK
        phishing_url = "http://93.184.216.34/secure/bank-login-update-account/verify.php"
        res = client.post(
            "/security/analyze-link",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"url": phishing_url}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["verdict"] == "HIGH RISK"

        scan_id = data["scan_id"]
        locations = self.db.query(ThreatLocation).filter(
            ThreatLocation.security_scan_id == scan_id
        ).all()
        assert len(locations) >= 1
        assert locations[0].country == "United States"
        assert locations[0].lookup_status == "SUCCESS"

    # 18. Geolocation failure does not fail link scanning
    def test_18_geolocation_failure_does_not_fail_link_scanning(self):
        set_geolocation_provider(MockFailureProvider())
        test_id = secrets.token_hex(4)
        user = User(full_name=f"Fail User {test_id}", email=f"fail_{test_id}@kavach.ai", role="user")
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        user_token = create_access_token({"sub": str(user.id), "role": "user"})
        phishing_url = "http://93.184.216.34/secure/fake-paypal-verify"
        res = client.post(
            "/security/analyze-link",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"url": phishing_url}
        )
        # Link analysis must still succeed with 200 OK!
        assert res.status_code == 200
        data = res.json()
        assert data["verdict"] == "HIGH RISK"
        assert data["scan_id"] is not None

        # Threat location row recorded as LOOKUP_FAILED
        scan_id = data["scan_id"]
        loc = self.db.query(ThreatLocation).filter(
            ThreatLocation.security_scan_id == scan_id
        ).first()
        assert loc is not None
        assert loc.lookup_status == "LOOKUP_FAILED"

    # 19. No fake coordinates are generated on failure or private IP
    def test_19_no_fake_coordinates_generated(self):
        set_geolocation_provider(MockFailureProvider())
        res_fail = geolocate_ip("93.184.216.34")
        assert res_fail.get("latitude") is None
        assert res_fail.get("longitude") is None

        res_priv = geolocate_ip("192.168.1.1")
        assert res_priv["status"] == "PRIVATE_IP"
        assert res_priv.get("latitude") is None
        assert res_priv.get("longitude") is None

    # 20. Accuracy radius is preserved when provider supplies it
    def test_20_accuracy_radius_preserved_when_supplied(self):
        set_geolocation_provider(MockSuccessProvider(accuracy_radius=42.5))
        res = geolocate_ip("93.184.216.34")
        assert res["accuracy_radius"] == 42.5

    # 21. NULL accuracy_radius is accepted when provider does not supply it
    def test_21_null_accuracy_radius_accepted(self):
        set_geolocation_provider(MockSuccessProvider(accuracy_radius=None))
        res = geolocate_ip("93.184.216.34")
        assert res["accuracy_radius"] is None


if __name__ == "__main__":
    pytest.main(["-v", __file__])
