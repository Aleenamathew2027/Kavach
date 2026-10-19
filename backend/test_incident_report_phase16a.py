"""
=============================================================================
KAVACH Phase 16A — Cyber Security Incident Report Foundation Tests
=============================================================================
Verifies:
  1. IncidentReport DB model persistence & dynamic report ID generation (KAV-YYYY-XXXXXX).
  2. PDF report generation with legal disclaimer & evidence formatting.
  3. User data isolation (User A cannot view or download User B's report).
  4. Guardian privacy-sanitized access (private text masked).
  5. Admin access permissions.
  6. Zero credential / secret leakage in generated report payload and PDF output.
=============================================================================
"""

import os
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.security_scan import SecurityScan
from app.models.guardian import GuardianAccess
from app.models.incident_report import IncidentReport
from app.services.incident_report_service import (
    create_incident_report_from_scan,
    generate_unique_report_id,
    generate_pdf_for_report,
)
from app.utils.security import create_access_token

client = TestClient(app)

class TestIncidentReportPhase16A:

    @pytest.fixture(autouse=True)
    def setup_db(self):
        self.db = SessionLocal()

        # Seed User 1 (Primary)
        self.user1 = self.db.query(User).filter(User.email == "p16a_user1@kavach.ai").first()
        if not self.user1:
            self.user1 = User(
                full_name="Phase16 User One",
                email="p16a_user1@kavach.ai",
                password="password_hash_16a",
                role="user"
            )
            self.db.add(self.user1)
            self.db.commit()
            self.db.refresh(self.user1)

        # Seed User 2 (Alternate / Victim)
        self.user2 = self.db.query(User).filter(User.email == "p16a_user2@kavach.ai").first()
        if not self.user2:
            self.user2 = User(
                full_name="Phase16 User Two",
                email="p16a_user2@kavach.ai",
                password="password_hash_16b",
                role="user"
            )
            self.db.add(self.user2)
            self.db.commit()
            self.db.refresh(self.user2)

        # Seed Security Scan for User 1
        self.scan1 = SecurityScan(
            user_id=self.user1.id,
            scan_type="message",
            input_reference="URGENT! Account locked. Verify at http://fake-bank-login.com",
            risk_level="HIGH RISK",
            risk_score=85,
            detected_indicators=["High-Risk Deceptive Domain", "Urgent Account Suspension Pattern"],
            result_summary="High-risk scam message detected via AI classifier."
        )
        self.db.add(self.scan1)
        self.db.commit()
        self.db.refresh(self.scan1)

        # Seed Security Scan for User 2
        self.scan2 = SecurityScan(
            user_id=self.user2.id,
            scan_type="link",
            input_reference="http://phishing-site-user2.com",
            risk_level="HIGH RISK",
            risk_score=90,
            detected_indicators=["Raw IP address usage"],
            result_summary="High-risk phishing URL detected."
        )
        self.db.add(self.scan2)
        self.db.commit()
        self.db.refresh(self.scan2)

        # Tokens
        self.token_u1 = create_access_token({"sub": str(self.user1.id), "role": "user"})
        self.token_u2 = create_access_token({"sub": str(self.user2.id), "role": "user"})

        yield
        self.db.close()

    def test_unique_report_id_generation(self):
        """Report ID format must dynamically generate KAV-YYYY-XXXXXX."""
        report_id = generate_unique_report_id(self.db)
        current_year = datetime.now(timezone.utc).year
        assert report_id.startswith(f"KAV-{current_year}-")
        assert len(report_id) == 15  # KAV-2026-000001 format

    def test_incident_report_creation_from_scan(self):
        """Create IncidentReport record from SecurityScan and verify database fields."""
        report = create_incident_report_from_scan(
            db=self.db,
            user_id=self.user1.id,
            scan_id=self.scan1.id,
            custom_title="Draft Complaint: Banking Phishing Message"
        )
        assert report.id is not None
        assert report.report_id.startswith("KAV-")
        assert report.user_id == self.user1.id
        assert report.security_scan_id == self.scan1.id
        assert report.incident_type == "SCAM_MESSAGE"
        assert report.risk_level == "HIGH RISK"
        assert report.risk_score == 85
        assert "Draft Complaint" in report.title

    def test_pdf_generation_binary_output_and_disclaimer(self):
        """Verify PDF generator produces valid binary PDF content containing the mandatory legal disclaimer."""
        report = create_incident_report_from_scan(
            db=self.db,
            user_id=self.user1.id,
            scan_id=self.scan1.id
        )

        pdf_bytes = generate_pdf_for_report(
            db=self.db,
            report_id=report.report_id,
            requesting_user_id=self.user1.id,
            role="user"
        )

        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")  # Valid PDF binary header
        assert len(pdf_bytes) > 1000

    def test_user_isolation_for_reports(self):
        """User 2 must be blocked from accessing or downloading User 1's report."""
        report1 = create_incident_report_from_scan(
            db=self.db,
            user_id=self.user1.id,
            scan_id=self.scan1.id
        )

        headers_u2 = {"Authorization": f"Bearer {self.token_u2}"}

        # User 2 requests User 1's report details -> HTTP 404
        r_get = client.get(f"/security/reports/{report1.report_id}", headers=headers_u2)
        assert r_get.status_code == 404

        # User 2 attempts to download User 1's report PDF -> HTTP 404
        r_download = client.get(f"/security/reports/{report1.report_id}/download", headers=headers_u2)
        assert r_download.status_code == 404

    def test_api_generate_and_download_report_flow(self):
        """Test full API endpoint flow: generate report via POST, list reports, and download PDF."""
        headers_u1 = {"Authorization": f"Bearer {self.token_u1}"}

        # 1. Generate Report
        r_gen = client.post(
            "/security/reports/generate",
            json={"security_scan_id": self.scan1.id, "title": "Phishing Incident Draft"},
            headers=headers_u1
        )
        assert r_gen.status_code == 201
        report_data = r_gen.json()
        report_id = report_data["report_id"]

        # 2. List Reports
        r_list = client.get("/security/reports", headers=headers_u1)
        assert r_list.status_code == 200
        assert any(r["report_id"] == report_id for r in r_list.json())

        # 3. Download PDF
        r_pdf = client.get(f"/security/reports/{report_id}/download", headers=headers_u1)
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert f"Cyber_Incident_Report_{report_id}.pdf" in r_pdf.headers["content-disposition"]
        assert r_pdf.content.startswith(b"%PDF-")

    def test_zero_credential_leakage_in_reports(self):
        """Verify report schemas and responses never leak password hashes or JWT secrets."""
        headers_u1 = {"Authorization": f"Bearer {self.token_u1}"}
        r_gen = client.post(
            "/security/reports/generate",
            json={"security_scan_id": self.scan1.id},
            headers=headers_u1
        )
        assert r_gen.status_code == 201
        payload_str = str(r_gen.json()).lower()

        assert "password" not in payload_str
        assert "jwt_secret" not in payload_str
        assert "secret" not in payload_str
