"""
=============================================================================
KAVACH — Regression Test Suite: Trusted Guardian Access Code Authentication
=============================================================================
Tests:
  A. Authenticated USER → POST /guardian/generate-code → 200 OK
  B. No Authorization header → 401 Unauthorized
  C. Invalid / expired token → 401 Unauthorized
  D. Guardian token cannot generate a new protected-user guardian code (403 Forbidden)
  E. Generated code remains exactly 6 numeric digits
  F. Generated code belongs to the authenticated user and prior active codes are revoked
  G. Existing /guardian/verify-code behavior still works (exchanges 6-digit code for guardian JWT)
  H. Unaffected endpoints: GET /users/me, GET /security/reports, GET /security/alerts, GET /security/summary
=============================================================================
"""

import os
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.guardian import GuardianAccess
from app.utils.security import create_access_token, verify_password

client = TestClient(app)


class TestGuardianCodeAuthRegression:

    @pytest.fixture(autouse=True)
    def setup_users(self):
        self.db = SessionLocal()

        # 1. Primary test user (role: "user")
        self.user = self.db.query(User).filter(User.email == "guardian_code_test_user@kavach.ai").first()
        if not self.user:
            self.user = User(
                full_name="Guardian Test User",
                email="guardian_code_test_user@kavach.ai",
                password="hashed_pwd_guardian_test_123",
                role="user"
            )
            self.db.add(self.user)
            self.db.commit()
            self.db.refresh(self.user)

        # 2. Second user (unrelated user, role: "user")
        self.user2 = self.db.query(User).filter(User.email == "guardian_code_test_user2@kavach.ai").first()
        if not self.user2:
            self.user2 = User(
                full_name="Guardian Test User Two",
                email="guardian_code_test_user2@kavach.ai",
                password="hashed_pwd_guardian_test_456",
                role="user"
            )
            self.db.add(self.user2)
            self.db.commit()
            self.db.refresh(self.user2)

        # Tokens
        self.user_token = create_access_token({"sub": str(self.user.id), "role": "user"})
        self.user2_token = create_access_token({"sub": str(self.user2.id), "role": "user"})
        self.guardian_token = create_access_token({
            "sub": str(self.user.id),
            "role": "guardian",
            "guardian_access_id": 99999
        })

        yield
        self.db.close()

    def test_a_authenticated_user_generates_code_200(self):
        """A. Authenticated USER → POST /guardian/generate-code → 200 OK."""
        res = client.post(
            "/guardian/generate-code",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert "code" in data
        assert "expires_at" in data
        assert "message" in data

    def test_b_no_authorization_header_returns_401(self):
        """B. Missing Authorization header → 401 Unauthorized."""
        res = client.post("/guardian/generate-code")
        assert res.status_code == 401
        data = res.json()
        assert data.get("detail") == "Authentication credentials were not provided"

    def test_c_invalid_token_returns_401(self):
        """C. Invalid or expired token → 401 Unauthorized."""
        # 1. Malformed token
        res = client.post(
            "/guardian/generate-code",
            headers={"Authorization": "Bearer invalid.jwt.token"}
        )
        assert res.status_code == 401

        # 2. Expired token
        expired_token = create_access_token(
            {"sub": str(self.user.id), "role": "user"},
            expires_delta=timedelta(seconds=-60)
        )
        res_expired = client.post(
            "/guardian/generate-code",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert res_expired.status_code == 401

    def test_d_guardian_token_cannot_generate_code(self):
        """D. Guardian token cannot generate a new guardian code (403 Forbidden)."""
        res = client.post(
            "/guardian/generate-code",
            headers={"Authorization": f"Bearer {self.guardian_token}"}
        )
        assert res.status_code == 403
        data = res.json()
        assert "Access forbidden" in data.get("detail", "")

    def test_e_generated_code_is_six_numeric_digits(self):
        """E. Generated code remains exactly 6 numeric digits."""
        res = client.post(
            "/guardian/generate-code",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        assert res.status_code == 200
        code = res.json()["code"]
        assert len(code) == 6
        assert code.isdigit()

    def test_f_generated_code_belongs_to_authenticated_user_and_revokes_prior(self):
        """F. Generated code belongs to authenticated user and prior active codes are deactivated."""
        # Generate code 1
        res1 = client.post(
            "/guardian/generate-code",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        assert res1.status_code == 200
        code1 = res1.json()["code"]

        # Generate code 2
        res2 = client.post(
            "/guardian/generate-code",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        assert res2.status_code == 200
        code2 = res2.json()["code"]

        # In DB: Only code 2 should be active for this user
        db = SessionLocal()
        active_codes = db.query(GuardianAccess).filter(
            GuardianAccess.user_id == self.user.id,
            GuardianAccess.is_active == True
        ).all()

        assert len(active_codes) == 1
        active_access = active_codes[0]
        assert active_access.user_id == self.user.id
        assert verify_password(code2, active_access.code_hash)
        assert not verify_password(code1, active_access.code_hash)
        db.close()

    def test_g_verify_code_exchanges_for_guardian_jwt(self):
        """G. Existing /guardian/verify-code behavior still works with generated code."""
        # 1. User generates code
        res_gen = client.post(
            "/guardian/generate-code",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        assert res_gen.status_code == 200
        code = res_gen.json()["code"]

        # 2. Guardian verifies code
        res_verify = client.post(
            "/guardian/verify-code",
            json={"code": code}
        )
        assert res_verify.status_code == 200
        data = res_verify.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "guardian"

    def test_h_unaffected_user_endpoints(self):
        """H. Verify existing user endpoints remain fully functioning."""
        headers = {"Authorization": f"Bearer {self.user_token}"}

        # 1. GET /users/me
        res_me = client.get("/users/me", headers=headers)
        assert res_me.status_code == 200
        assert res_me.json()["email"] == self.user.email

        # 2. GET /security/alerts
        res_alerts = client.get("/security/alerts", headers=headers)
        assert res_alerts.status_code == 200

        # 3. GET /security/reports
        res_reports = client.get("/security/reports", headers=headers)
        assert res_reports.status_code == 200

        # 4. GET /security/summary
        res_summary = client.get("/security/summary", headers=headers)
        assert res_summary.status_code == 200
