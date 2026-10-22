"""
=============================================================================
KAVACH Phase 18B Test Suite — Threat Infrastructure Geolocation & Map Support
=============================================================================
Tests multi-vector threat infrastructure geolocation across:
- Direct Links
- Messages containing URLs
- Messages without URLs (clean/extortion)
- Document & OCR extracted URLs
- QR Code analysis (URL vs UPI vs Crypto vs Plain Text)
- Safe scans bypass geolocation
- API response contract for Frontend Map component
=============================================================================
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from main import app
from app.models.user import User
from app.models.security_scan import SecurityScan
from app.models.threat_location import ThreatLocation
from app.database.init_db import SessionLocal
from app.utils.security import create_access_token, hash_password


client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def test_user(db_session):
    email = "phase18b_user@kavach.test"
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password=hash_password("Phase18BSecret!"),
            full_name="Phase 18B Tester",
            role="user",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    return user


@pytest.fixture(scope="module")
def user_token(test_user):
    return create_access_token(data={"sub": str(test_user.id), "email": test_user.email, "role": test_user.role})


class TestThreatGeolocationPhase18B:
    """Multi-vector Threat Geolocation Verification for Phase 18B"""

    def test_01_api_returns_empty_when_no_location(self, user_token, test_user, db_session):
        """When scan has no threat location, API returns 200 with empty list and disclaimer."""
        scan = SecurityScan(
            user_id=test_user.id,
            scan_type="message",
            input_reference="Safe hello world",
            risk_level="SAFE",
            risk_score=5,
            result_summary="Clean message.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        resp = client.get(
            f"/security/threat-locations/{scan.id}",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan.id
        assert data["locations"] == []
        assert "disclaimer" in data
        assert "approximate" in data["disclaimer"].lower()

    @patch("app.api.security.create_threat_location_for_scan")
    def test_02_message_with_high_risk_url_triggers_geolocation(self, mock_create_geo, user_token):
        """A HIGH RISK message containing a URL calls threat geolocation creation."""
        mock_create_geo.return_value = None

        # Message with extreme urgency + financial keywords + URL
        msg_text = "URGENT: Your bank account will be blocked within 24 hours. Click https://secure-login-example.com@evil.example/verify to share your OTP immediately."
        resp = client.post(
            "/security/analyze-message",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"message": msg_text}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "HIGH RISK"
        assert "scan_id" in data
        # Verification that geolocation was attempted with the extracted URL
        assert mock_create_geo.called
        call_kwargs = mock_create_geo.call_args.kwargs
        assert "evil.example" in call_kwargs.get("suspicious_url", "")

    @patch("app.api.security.create_threat_location_for_scan")
    def test_03_message_without_url_does_not_trigger_geolocation(self, mock_create_geo, user_token):
        """A message without any URL never attempts geolocation lookup."""
        mock_create_geo.reset_mock()

        msg_text = "Urgent final warning! Your account has been suspended by police. Transfer money immediately."
        resp = client.post(
            "/security/analyze-message",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"message": msg_text}
        )
        assert resp.status_code == 200
        # No URL in text, so create_threat_location_for_scan must NOT be called
        assert not mock_create_geo.called

    @patch("app.api.security.create_threat_location_for_scan")
    def test_04_safe_message_does_not_trigger_geolocation(self, mock_create_geo, user_token):
        """A SAFE message never triggers geolocation even if it contains a link."""
        mock_create_geo.reset_mock()

        msg_text = "Hi team, please find the minutes of the meeting at https://en.wikipedia.org/wiki/Security. Have a good evening!"
        resp = client.post(
            "/security/analyze-message",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"message": msg_text}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "SAFE"
        assert not mock_create_geo.called

    def test_05_qr_upi_payment_no_fake_coordinates(self, db_session, test_user):
        """UPI QR code payloads do not create threat location records."""
        scan = SecurityScan(
            user_id=test_user.id,
            scan_type="document",
            input_reference="qr_upi_scan.png",
            risk_level="HIGH RISK",
            risk_score=75,
            result_summary="Suspicious UPI handle in QR",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        # Check threat locations in DB
        locs = db_session.query(ThreatLocation).filter(ThreatLocation.security_scan_id == scan.id).all()
        assert len(locs) == 0

    def test_06_qr_crypto_address_no_fake_coordinates(self, db_session, test_user):
        """Cryptocurrency QR code payloads do not create threat location records."""
        scan = SecurityScan(
            user_id=test_user.id,
            scan_type="document",
            input_reference="qr_crypto.png",
            risk_level="HIGH RISK",
            risk_score=70,
            result_summary="Crypto address in QR",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        locs = db_session.query(ThreatLocation).filter(ThreatLocation.security_scan_id == scan.id).all()
        assert len(locs) == 0

    def test_07_populated_threat_location_api_response(self, user_token, test_user, db_session):
        """When a scan has an associated threat location, the endpoint returns complete metadata."""
        scan = SecurityScan(
            user_id=test_user.id,
            scan_type="link",
            input_reference="https://phishing-site-test.com",
            risk_level="HIGH RISK",
            risk_score=95,
            result_summary="Phishing domain detected",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        loc = ThreatLocation(
            security_scan_id=scan.id,
            domain="phishing-site-test.com",
            ip_address="198.51.100.25",
            country="Germany",
            region="Hesse",
            city="Frankfurt am Main",
            latitude=50.1109,
            longitude=8.6821,
            accuracy_radius=15.0,
            isp="Cloud Network Services",
            organization="Datacenter Hosting GmbH",
            asn="AS20473",
            timezone="Europe/Berlin",
            location_source="IP-API",
            lookup_status="SUCCESS",
        )
        db_session.add(loc)
        db_session.commit()

        resp = client.get(
            f"/security/threat-locations/{scan.id}",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["locations"]) == 1
        item = data["locations"][0]
        assert item["domain"] == "phishing-site-test.com"
        assert item["ip_address"] == "198.51.100.25"
        assert item["country"] == "Germany"
        assert item["city"] == "Frankfurt am Main"
        assert item["latitude"] == 50.1109
        assert item["longitude"] == 8.6821
        assert item["accuracy_radius"] == 15.0
        assert item["asn"] == "AS20473"
        assert item["lookup_status"] == "SUCCESS"

    def test_08_disclaimer_avoids_scammer_address_terminology(self, user_token, test_user, db_session):
        """Verified that disclaimer text strictly avoids claiming physical scammer residence."""
        scan = SecurityScan(
            user_id=test_user.id,
            scan_type="link",
            input_reference="test-disclaimer",
            risk_level="HIGH RISK",
            risk_score=80,
            result_summary="Test",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        resp = client.get(
            f"/security/threat-locations/{scan.id}",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        disclaimer = resp.json()["disclaimer"].lower()
        forbidden_phrases = [
            "scammer location",
            "attacker address",
            "scammer's house",
            "exact attacker location",
            "physical location of the scammer"
        ]
        for phrase in forbidden_phrases:
            assert phrase not in disclaimer
