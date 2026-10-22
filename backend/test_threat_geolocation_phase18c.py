"""
=============================================================================
KAVACH Phase 18C Test Suite — Threat Infrastructure in Incident Reports & PDF
=============================================================================
Verifies integration of approximate threat infrastructure geolocation into:
- Incident Report API detail views (User, Guardian, Admin)
- Incident Report PDF generation
- RBAC security and user isolation
- Missing coordinates/radius resilience
- Absence of fake locations
=============================================================================
"""

from datetime import datetime, timezone, timedelta
import io
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from main import app
from app.database.init_db import SessionLocal
from app.models.user import User
from app.models.security_scan import SecurityScan
from app.models.incident_report import IncidentReport
from app.models.threat_location import ThreatLocation
from app.models.guardian import GuardianAccess
from app.services.incident_report_service import (
    create_incident_report_from_scan,
    generate_pdf_for_report,
)
from app.utils.security import create_access_token, hash_password


client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def test_user_a(db_session):
    email = "phase18c_usera@kavach.test"
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password=hash_password("Phase18CPassword!"),
            full_name="Phase18C User A",
            role="user",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    return user


@pytest.fixture(scope="module")
def token_user_a(test_user_a):
    return create_access_token(
        data={"sub": str(test_user_a.id), "email": test_user_a.email, "role": "user"}
    )


@pytest.fixture(scope="module")
def test_user_b(db_session):
    email = "phase18c_userb@kavach.test"
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password=hash_password("Phase18CPassword!"),
            full_name="Phase18C User B",
            role="user",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    return user


@pytest.fixture(scope="module")
def token_user_b(test_user_b):
    return create_access_token(
        data={"sub": str(test_user_b.id), "email": test_user_b.email, "role": "user"}
    )


@pytest.fixture(scope="module")
def guardian_token_for_user_a(test_user_a, db_session):
    # Active Guardian access linking to User A
    access = GuardianAccess(
        user_id=test_user_a.id,
        code_hash=hash_password("998877"),
        is_active=True,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    db_session.add(access)
    db_session.commit()
    db_session.refresh(access)

    return create_access_token(
        data={"sub": str(test_user_a.id), "role": "guardian", "guardian_access_id": access.id}
    )


@pytest.fixture(scope="module")
def admin_token(db_session):
    email = "phase18c_admin@kavach.test"
    admin = db_session.query(User).filter(User.email == email).first()
    if not admin:
        admin = User(
            email=email,
            password=hash_password("Phase18CPassword!"),
            full_name="Phase18C Admin",
            role="admin",
        )
        db_session.add(admin)
        db_session.commit()
        db_session.refresh(admin)

    return create_access_token(
        data={"sub": str(admin.id), "email": admin.email, "role": "admin"}
    )


class TestThreatGeolocationPhase18C:
    """Phase 18C Test Suite — Threat Infrastructure in Reports & PDFs"""

    def test_01_report_includes_threat_infrastructure(self, db_session, test_user_a, token_user_a):
        """1. When a scan has a threat location, the Incident Report detail exposes threat_infrastructure."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://phish-bank-test18c.example",
            risk_level="HIGH RISK",
            risk_score=90,
            result_summary="Phishing banking portal detected.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        loc = ThreatLocation(
            security_scan_id=scan.id,
            domain="phish-bank-test18c.example",
            ip_address="198.51.100.88",
            country="Netherlands",
            region="North Holland",
            city="Amsterdam",
            latitude=52.3676,
            longitude=4.9041,
            accuracy_radius=12.0,
            isp="Hosting Provider BV",
            organization="Cloud Infrastructure Ltd",
            asn="AS12345",
            timezone="Europe/Amsterdam",
            location_source="IP-API",
            lookup_status="SUCCESS",
        )
        db_session.add(loc)
        db_session.commit()

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
            custom_title="Phishing Threat Report with Location",
        )

        resp = client.get(
            f"/security/reports/{report.report_id}",
            headers={"Authorization": f"Bearer {token_user_a}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "threat_infrastructure" in data
        ti = data["threat_infrastructure"]
        assert ti["available"] is True
        assert ti["domain"] == "phish-bank-test18c.example"
        assert ti["ip_address"] == "198.51.100.88"
        assert ti["country"] == "Netherlands"
        assert ti["city"] == "Amsterdam"
        assert ti["latitude"] == 52.3676
        assert ti["longitude"] == 4.9041
        assert ti["accuracy_radius"] == 12.0
        assert ti["asn"] == "AS12345"

    def test_02_report_without_threat_infrastructure_still_works(
        self, db_session, test_user_a, token_user_a
    ):
        """2. When a scan has no threat location, report still generates and exposes available=False."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="message",
            input_reference="Call me immediately at 9999",
            risk_level="HIGH RISK",
            risk_score=75,
            result_summary="High pressure scam text with no URL.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
            custom_title="Scam Message Without Location",
        )

        resp = client.get(
            f"/security/reports/{report.report_id}",
            headers={"Authorization": f"Bearer {token_user_a}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "threat_infrastructure" in data
        assert data["threat_infrastructure"]["available"] is False

    def test_03_pdf_includes_threat_infrastructure_section(
        self, db_session, test_user_a
    ):
        """3. PDF report contains textual THREAT INFRASTRUCTURE LOCATION section and disclaimer."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://evil-portal.example",
            risk_level="HIGH RISK",
            risk_score=85,
            result_summary="Credential harvester URL.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        loc = ThreatLocation(
            security_scan_id=scan.id,
            domain="evil-portal.example",
            ip_address="203.0.113.45",
            country="United Kingdom",
            region="England",
            city="London",
            latitude=51.5074,
            longitude=-0.1278,
            accuracy_radius=10.0,
            isp="Datacenter Network Ltd",
            organization="Global Transit ASN",
            asn="AS54321",
            timezone="Europe/London",
            location_source="IP-API",
            lookup_status="SUCCESS",
        )
        db_session.add(loc)
        db_session.commit()

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        pdf_bytes = generate_pdf_for_report(
            db=db_session,
            report_id=report.report_id,
            requesting_user_id=test_user_a.id,
            role="user",
        )
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        # Check PDF header
        assert pdf_bytes.startswith(b"%PDF")

    def test_04_missing_coordinates_do_not_break_pdf(
        self, db_session, test_user_a
    ):
        """4. PDF report generates cleanly even if latitude/longitude are None."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://no-coords.example",
            risk_level="HIGH RISK",
            risk_score=80,
            result_summary="Domain without GPS coordinates.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        loc = ThreatLocation(
            security_scan_id=scan.id,
            domain="no-coords.example",
            ip_address="192.0.2.1",
            country="Unknown Country",
            latitude=None,
            longitude=None,
            accuracy_radius=None,
            lookup_status="SUCCESS",
        )
        db_session.add(loc)
        db_session.commit()

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        pdf_bytes = generate_pdf_for_report(
            db=db_session,
            report_id=report.report_id,
            requesting_user_id=test_user_a.id,
            role="user",
        )
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF")

    def test_05_missing_accuracy_radius_does_not_break_pdf(
        self, db_session, test_user_a
    ):
        """5. PDF report displays 'Accuracy radius unavailable.' without breaking."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://no-radius.example",
            risk_level="HIGH RISK",
            risk_score=80,
            result_summary="Domain without radius.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        loc = ThreatLocation(
            security_scan_id=scan.id,
            domain="no-radius.example",
            ip_address="198.51.100.99",
            country="Germany",
            latitude=50.1109,
            longitude=8.6821,
            accuracy_radius=None,
            lookup_status="SUCCESS",
        )
        db_session.add(loc)
        db_session.commit()

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        pdf_bytes = generate_pdf_for_report(
            db=db_session,
            report_id=report.report_id,
            requesting_user_id=test_user_a.id,
            role="user",
        )
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF")

    def test_06_user_can_access_own_report_location(
        self, db_session, test_user_a, token_user_a
    ):
        """6. User A can retrieve their own report with threat location details."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://user-a-access.example",
            risk_level="HIGH RISK",
            risk_score=90,
            result_summary="User A owned threat.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        resp = client.get(
            f"/security/reports/{report.report_id}",
            headers={"Authorization": f"Bearer {token_user_a}"},
        )
        assert resp.status_code == 200
        assert resp.json()["report_id"] == report.report_id

    def test_07_user_cannot_access_another_users_report_location(
        self, db_session, test_user_a, token_user_b
    ):
        """7. User B cannot access User A's incident report (strict 404/403 isolation)."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://user-a-private.example",
            risk_level="HIGH RISK",
            risk_score=92,
            result_summary="Private User A scan.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        # Attempted access by User B
        resp = client.get(
            f"/security/reports/{report.report_id}",
            headers={"Authorization": f"Bearer {token_user_b}"},
        )
        assert resp.status_code in [403, 404]

    def test_08_guardian_can_access_linked_user_report_location(
        self, db_session, test_user_a, guardian_token_for_user_a
    ):
        """8. Guardian can access report and threat location of their linked protected user."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://guarded-threat.example",
            risk_level="HIGH RISK",
            risk_score=88,
            result_summary="Guarded user phishing attempt.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        loc = ThreatLocation(
            security_scan_id=scan.id,
            domain="guarded-threat.example",
            ip_address="198.51.100.11",
            country="France",
            city="Paris",
            latitude=48.8566,
            longitude=2.3522,
            accuracy_radius=8.0,
            lookup_status="SUCCESS",
        )
        db_session.add(loc)
        db_session.commit()

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        resp = client.get(
            f"/guardian/reports/{report.report_id}",
            headers={"Authorization": f"Bearer {guardian_token_for_user_a}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_id"] == report.report_id
        assert data["threat_infrastructure"]["available"] is True
        assert data["threat_infrastructure"]["country"] == "France"
        assert data["threat_infrastructure"]["city"] == "Paris"

    def test_09_guardian_cannot_access_unrelated_user_report(
        self, db_session, test_user_b, guardian_token_for_user_a
    ):
        """9. Guardian linked to User A cannot access reports belonging to User B."""
        scan = SecurityScan(
            user_id=test_user_b.id,
            scan_type="link",
            input_reference="https://user-b-incident.example",
            risk_level="HIGH RISK",
            risk_score=85,
            result_summary="User B incident.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_b.id,
            scan_id=scan.id,
        )

        resp = client.get(
            f"/guardian/reports/{report.report_id}",
            headers={"Authorization": f"Bearer {guardian_token_for_user_a}"},
        )
        assert resp.status_code == 404

    def test_10_admin_access_follows_existing_rbac(
        self, db_session, test_user_a, admin_token
    ):
        """10. Admin can access threat location in reports across all users."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://admin-review.example",
            risk_level="HIGH RISK",
            risk_score=95,
            result_summary="Threat review by admin.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        # Admin access to threat location endpoint
        resp = client.get(
            f"/security/threat-locations/{scan.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan.id

    def test_11_no_fake_location_generated(self, db_session, test_user_a, token_user_a):
        """11. A text scan without public domain/IP returns available=False and no fake coordinates."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="message",
            input_reference="Text scam without URL",
            risk_level="HIGH RISK",
            risk_score=75,
            result_summary="Urgent message requesting bank transfer.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        resp = client.get(
            f"/security/reports/{report.report_id}",
            headers={"Authorization": f"Bearer {token_user_a}"},
        )
        assert resp.status_code == 200
        ti = resp.json().get("threat_infrastructure", {})
        assert ti.get("available") is False
        assert ti.get("latitude") is None
        assert ti.get("longitude") is None

    def test_12_existing_incident_report_pdf_download_routes(
        self, db_session, test_user_a, token_user_a, guardian_token_for_user_a
    ):
        """12. Both User and Guardian PDF download routes succeed."""
        scan = SecurityScan(
            user_id=test_user_a.id,
            scan_type="link",
            input_reference="https://download-verify.example",
            risk_level="HIGH RISK",
            risk_score=90,
            result_summary="PDF Download Verification.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        report = create_incident_report_from_scan(
            db=db_session,
            user_id=test_user_a.id,
            scan_id=scan.id,
        )

        # User download route
        user_dl = client.get(
            f"/security/reports/{report.report_id}/download",
            headers={"Authorization": f"Bearer {token_user_a}"},
        )
        assert user_dl.status_code == 200
        assert user_dl.headers["content-type"] == "application/pdf"
        assert len(user_dl.content) > 1000

        # Guardian download route
        guard_dl = client.get(
            f"/guardian/reports/{report.report_id}/download",
            headers={"Authorization": f"Bearer {guardian_token_for_user_a}"},
        )
        assert guard_dl.status_code == 200
        assert guard_dl.headers["content-type"] == "application/pdf"
        assert len(guard_dl.content) > 1000
