"""
=============================================================================
KAVACH Phase 16C — Guardian Dashboard Cyber Incident Reports Backend Tests
=============================================================================
Tests:
  A. Guardian report list returns only linked user's reports.
  B. Guardian cannot access another user's report (HTTP 404).
  C. Unauthenticated access to guardian report endpoints is rejected (HTTP 401/403).
  D. Normal user role cannot access /guardian/reports (HTTP 403).
  E. Guardian can download the sanitized PDF of their linked user's report.
  F. Guardian report list returns correct report_id, risk_level, and incident_type.
  G. Empty report state: Guardian with no high-risk reports gets empty list [].
  H. GET /guardian/reports/{report_id} returns correct detail for valid report.
  I. User incident report list endpoint still works (existing Phase 16A behavior).
  J. Existing Guardian dashboard still works (no regressions).
=============================================================================
"""

import os
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.security_scan import SecurityScan
from app.models.security_alert import SecurityAlert
from app.models.guardian import GuardianAccess
from app.models.incident_report import IncidentReport
from app.services.incident_report_service import create_incident_report_from_scan
from app.utils.security import create_access_token

client = TestClient(app)


class TestGuardianReportsPhase16C:

    @pytest.fixture(autouse=True)
    def setup_db(self):
        self.db = SessionLocal()

        # Primary User (the guarded user)
        self.user1 = self.db.query(User).filter(User.email == "p16c_user1@kavach.ai").first()
        if not self.user1:
            self.user1 = User(
                full_name="Phase16C User One",
                email="p16c_user1@kavach.ai",
                password="password_hash_16c_1",
                role="user"
            )
            self.db.add(self.user1)
            self.db.commit()
            self.db.refresh(self.user1)

        # Second User (unrelated)
        self.user2 = self.db.query(User).filter(User.email == "p16c_user2@kavach.ai").first()
        if not self.user2:
            self.user2 = User(
                full_name="Phase16C User Two",
                email="p16c_user2@kavach.ai",
                password="password_hash_16c_2",
                role="user"
            )
            self.db.add(self.user2)
            self.db.commit()
            self.db.refresh(self.user2)

        # Active Guardian Access for User 1
        now = datetime.now(timezone.utc)
        self.guardian_access = self.db.query(GuardianAccess).filter(
            GuardianAccess.user_id == self.user1.id,
            GuardianAccess.is_active == True,
            GuardianAccess.expires_at > now
        ).first()

        if not self.guardian_access:
            self.guardian_access = GuardianAccess(
                user_id=self.user1.id,
                code_hash="test_code_hash_16c",
                is_active=True,
                expires_at=now + timedelta(hours=24)
            )
            self.db.add(self.guardian_access)
            self.db.commit()
            self.db.refresh(self.guardian_access)

        # Create a HIGH RISK scan and report for User 1
        self.scan1 = SecurityScan(
            user_id=self.user1.id,
            scan_type="message",
            input_reference="Test scam message for 16C",
            risk_level="HIGH RISK",
            risk_score=85,
            detected_indicators=["Urgency Tactics", "OTP Request"],
            result_summary="Phase 16C test high-risk scan"
        )
        self.db.add(self.scan1)
        self.db.commit()
        self.db.refresh(self.scan1)

        # Create incident report for User 1's scan
        self.report1 = create_incident_report_from_scan(
            db=self.db,
            user_id=self.user1.id,
            scan_id=self.scan1.id,
            custom_title="Phase 16C Test Incident Report"
        )

        # Create a separate HIGH RISK scan + report for User 2
        self.scan2 = SecurityScan(
            user_id=self.user2.id,
            scan_type="link",
            input_reference="http://phishing-test-16c.ru",
            risk_level="HIGH RISK",
            risk_score=90,
            detected_indicators=["Suspicious TLD"],
            result_summary="Phase 16C test phishing scan for user 2"
        )
        self.db.add(self.scan2)
        self.db.commit()
        self.db.refresh(self.scan2)

        self.report2 = create_incident_report_from_scan(
            db=self.db,
            user_id=self.user2.id,
            scan_id=self.scan2.id,
            custom_title="Phase 16C User 2 Report"
        )

        # Tokens
        self.token_u1 = create_access_token({"sub": str(self.user1.id), "role": "user"})
        self.token_u2 = create_access_token({"sub": str(self.user2.id), "role": "user"})
        self.token_g1 = create_access_token({
            "sub": str(self.user1.id),
            "role": "guardian",
            "guardian_access_id": self.guardian_access.id
        })

        yield
        self.db.close()

    def test_a_guardian_report_list_returns_only_linked_user_reports(self):
        """A. Guardian report list returns only reports belonging to their linked user."""
        headers_g1 = {"Authorization": f"Bearer {self.token_g1}"}
        res = client.get("/guardian/reports", headers=headers_g1)
        assert res.status_code == 200

        data = res.json()
        assert isinstance(data, list)

        # All returned reports must belong to User 1
        report_ids = [r["report_id"] for r in data]
        assert self.report1.report_id in report_ids

        # User 2's report must NOT appear in Guardian 1's list
        assert self.report2.report_id not in report_ids

    def test_b_guardian_cannot_access_other_users_report(self):
        """B. Guardian cannot access another user's report via detail endpoint (HTTP 404)."""
        headers_g1 = {"Authorization": f"Bearer {self.token_g1}"}
        # Attempt to access user2's report using guardian1's token
        res = client.get(f"/guardian/reports/{self.report2.report_id}", headers=headers_g1)
        assert res.status_code == 404

    def test_c_unauthenticated_access_rejected(self):
        """C. Unauthenticated requests to guardian report endpoints are rejected."""
        # No token
        res_list = client.get("/guardian/reports")
        assert res_list.status_code in (401, 403)

        res_detail = client.get(f"/guardian/reports/{self.report1.report_id}")
        assert res_detail.status_code in (401, 403)

        res_download = client.get(f"/guardian/reports/{self.report1.report_id}/download")
        assert res_download.status_code in (401, 403)

    def test_d_normal_user_cannot_access_guardian_report_endpoints(self):
        """D. Normal user token cannot access /guardian/reports (requires guardian role)."""
        headers_u1 = {"Authorization": f"Bearer {self.token_u1}"}

        res_list = client.get("/guardian/reports", headers=headers_u1)
        assert res_list.status_code == 403

        res_detail = client.get(f"/guardian/reports/{self.report1.report_id}", headers=headers_u1)
        assert res_detail.status_code == 403

    def test_e_guardian_can_download_sanitized_pdf(self):
        """E. Guardian can download the privacy-sanitized PDF for their linked user's report."""
        headers_g1 = {"Authorization": f"Bearer {self.token_g1}"}
        res = client.get(f"/guardian/reports/{self.report1.report_id}/download", headers=headers_g1)
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/pdf"
        assert res.content.startswith(b"%PDF-")

    def test_f_guardian_report_list_has_correct_fields(self):
        """F. Guardian report list returns correct report_id, risk_level, and incident_type."""
        headers_g1 = {"Authorization": f"Bearer {self.token_g1}"}
        res = client.get("/guardian/reports", headers=headers_g1)
        assert res.status_code == 200

        data = res.json()
        matching = [r for r in data if r["report_id"] == self.report1.report_id]
        assert len(matching) == 1

        rep = matching[0]
        assert rep["report_id"] == self.report1.report_id
        assert rep["risk_level"] == "HIGH RISK"
        assert rep["incident_type"] == "SCAM_MESSAGE"
        assert rep["risk_score"] == 85
        assert "title" in rep
        assert "summary" in rep
        assert "detected_at" in rep
        assert "created_at" in rep
        assert "status" in rep

    def test_g_empty_report_list_for_user_with_no_reports(self):
        """G. Guardian for a user with no reports gets empty list []."""
        # Create a fresh user with no scans
        db = SessionLocal()
        user_empty = db.query(User).filter(User.email == "p16c_empty@kavach.ai").first()
        if not user_empty:
            user_empty = User(
                full_name="Empty User 16C",
                email="p16c_empty@kavach.ai",
                password="hash_empty_16c",
                role="user"
            )
            db.add(user_empty)
            db.commit()
            db.refresh(user_empty)

        token_guardian_empty = create_access_token({
            "sub": str(user_empty.id),
            "role": "guardian",
            "guardian_access_id": 999999  # dummy id; list endpoint only filters by user_id
        })
        db.close()

        headers = {"Authorization": f"Bearer {token_guardian_empty}"}
        res = client.get("/guardian/reports", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_h_guardian_report_detail_returns_correct_data(self):
        """H. GET /guardian/reports/{report_id} returns correct detail for a valid report."""
        headers_g1 = {"Authorization": f"Bearer {self.token_g1}"}
        res = client.get(f"/guardian/reports/{self.report1.report_id}", headers=headers_g1)
        assert res.status_code == 200

        data = res.json()
        assert data["report_id"] == self.report1.report_id
        assert data["user_id"] == self.user1.id
        assert data["incident_type"] == "SCAM_MESSAGE"
        assert data["risk_level"] == "HIGH RISK"
        assert data["risk_score"] == 85

    def test_i_user_incident_report_list_still_works(self):
        """I. User's own /security/reports endpoint still works (Phase 16A regression check)."""
        headers_u1 = {"Authorization": f"Bearer {self.token_u1}"}
        res = client.get("/security/reports", headers=headers_u1)
        assert res.status_code == 200

        data = res.json()
        assert isinstance(data, list)
        report_ids = [r["report_id"] for r in data]
        assert self.report1.report_id in report_ids
        # User 1 should not see user 2's reports
        assert self.report2.report_id not in report_ids

    def test_j_guardian_dashboard_still_works(self):
        """J. Existing Guardian dashboard endpoint is unaffected (no regressions)."""
        headers_g1 = {"Authorization": f"Bearer {self.token_g1}"}
        res = client.get("/guardian/dashboard", headers=headers_g1)
        assert res.status_code == 200

        data = res.json()
        assert "role" in data
        assert data["role"] == "guardian"
        assert "guarded_user" in data
        assert "security_summary" in data
        assert "recent_alerts" in data
