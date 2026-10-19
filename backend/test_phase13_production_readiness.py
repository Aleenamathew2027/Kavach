"""
=============================================================================
KAVACH Phase 13 — Complete Production Readiness & End-to-End Security Suite
=============================================================================
Comprehensive security regression test suite covering:
  1. Backend Startup & Environment Hardening (Prod vs Dev mode JWT validation)
  2. Authentication & RBAC Isolation (User, Guardian, Admin role boundaries)
  3. Multi-Tenant User Data Isolation (Alert/Scan ownership checks)
  4. Security Scanner Isolation & Safety Guarantees:
     - No outbound HTTP requests during scanning (SSRF prevention)
     - Empty, corrupted, and unsupported files return UNSCANNABLE (never SAFE)
     - Oversized file (>10MB) rejection
     - Guardian alert feeds strip raw private content
  5. API Response Data Sanitization (Zero secret/credential leakage)
=============================================================================
"""

import os
import socket
import pytest
from datetime import datetime, timedelta, timezone
import jwt
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.security_alert import SecurityAlert
from app.models.security_scan import SecurityScan
from app.models.guardian import GuardianAccess
from app.utils.security import (
    create_access_token,
    validate_security_config,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
)

client = TestClient(app)

class TestPhase13ProductionReadiness:

    @pytest.fixture(autouse=True)
    def setup_db(self):
        self.db = SessionLocal()
        
        # User 1 (Primary User)
        self.user1 = self.db.query(User).filter(User.email == "p13_user1@kavach.ai").first()
        if not self.user1:
            self.user1 = User(
                full_name="Phase13 User One",
                email="p13_user1@kavach.ai",
                password="password_hash_1",
                role="user"
            )
            self.db.add(self.user1)
            self.db.commit()
            self.db.refresh(self.user1)

        # User 2 (Victim / Alternate User)
        self.user2 = self.db.query(User).filter(User.email == "p13_user2@kavach.ai").first()
        if not self.user2:
            self.user2 = User(
                full_name="Phase13 User Two",
                email="p13_user2@kavach.ai",
                password="password_hash_2",
                role="user"
            )
            self.db.add(self.user2)
            self.db.commit()
            self.db.refresh(self.user2)

        # Admin Account
        self.admin = self.db.query(User).filter(User.role == "admin").first()

        # Active Guardian Access Link for User 1
        now = datetime.now(timezone.utc)
        self.guardian_access = self.db.query(GuardianAccess).filter(
            GuardianAccess.user_id == self.user1.id,
            GuardianAccess.is_active == True,
            GuardianAccess.expires_at > now
        ).first()

        if not self.guardian_access:
            self.guardian_access = GuardianAccess(
                user_id=self.user1.id,
                code_hash="test_code_hash_13",
                is_active=True,
                expires_at=now + timedelta(hours=24)
            )
            self.db.add(self.guardian_access)
            self.db.commit()
            self.db.refresh(self.guardian_access)

        # Generate Tokens
        self.token_user1 = create_access_token({"sub": str(self.user1.id), "role": "user"})
        self.token_user2 = create_access_token({"sub": str(self.user2.id), "role": "user"})
        self.token_admin = create_access_token({"sub": str(self.admin.id), "role": "admin"}) if self.admin else None
        self.token_guardian = create_access_token({
            "sub": str(self.user1.id),
            "role": "guardian",
            "guardian_access_id": self.guardian_access.id
        })

        yield
        self.db.close()

    # -------------------------------------------------------------------------
    # 1. BACKEND STARTUP & CONFIGURATION HARDENING
    # -------------------------------------------------------------------------
    def test_startup_production_mode_secret_enforcement(self):
        """Verify production mode rejects missing/weak JWT secret keys."""
        # Weak default key in production mode -> ValueError
        with pytest.raises(ValueError, match="Production mode requires a strong custom JWT_SECRET_KEY"):
            validate_security_config(
                env="production",
                secret="kavach_default_secret_key_please_set_in_env",
                algo="HS256"
            )

        # Short key in production mode -> ValueError
        with pytest.raises(ValueError, match="Production mode requires a strong custom JWT_SECRET_KEY"):
            validate_security_config(
                env="production",
                secret="short_key_123",
                algo="HS256"
            )

        # Development mode allows local default
        validate_security_config(env="development", secret="kavach_default_secret_key_please_set_in_env", algo="HS256")

    # -------------------------------------------------------------------------
    # 2. AUTHENTICATION & ROLE-BASED ACCESS CONTROL (RBAC)
    # -------------------------------------------------------------------------
    def test_unauthenticated_and_invalid_token_rejection(self):
        """Verify unauthenticated or malformed requests return HTTP 401."""
        # No header
        res1 = client.get("/user/dashboard")
        assert res1.status_code == 401

        # Invalid token signature
        res2 = client.get("/user/dashboard", headers={"Authorization": "Bearer invalid.jwt.token"})
        assert res2.status_code == 401

    def test_expired_token_rejection(self):
        """Verify expired JWT tokens return HTTP 401."""
        expired_payload = {
            "sub": str(self.user1.id),
            "role": "user",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=5)
        }
        expired_token = jwt.encode(expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        res = client.get("/user/dashboard", headers={"Authorization": f"Bearer {expired_token}"})
        assert res.status_code == 401

    def test_role_boundaries_user_admin_guardian(self):
        """Verify strict isolation between User, Guardian, and Admin endpoints."""
        headers_u1 = {"Authorization": f"Bearer {self.token_user1}"}
        headers_g = {"Authorization": f"Bearer {self.token_guardian}"}

        # User cannot access Admin dashboard
        res_u_admin = client.get("/admin/dashboard", headers=headers_u1)
        assert res_u_admin.status_code == 403

        # User cannot access Guardian dashboard
        res_u_guard = client.get("/guardian/dashboard", headers=headers_u1)
        assert res_u_guard.status_code == 403

        # Guardian cannot access Admin dashboard
        res_g_admin = client.get("/admin/dashboard", headers=headers_g)
        assert res_g_admin.status_code == 403

        # Guardian cannot access User dashboard
        res_g_user = client.get("/user/dashboard", headers=headers_g)
        assert res_g_user.status_code == 403

        # Admin can access Admin dashboard
        if self.token_admin:
            res_a = client.get("/admin/dashboard", headers={"Authorization": f"Bearer {self.token_admin}"})
            assert res_a.status_code == 200

        # Guardian can access Guardian dashboard
        res_g = client.get("/guardian/dashboard", headers=headers_g)
        assert res_g.status_code == 200

    # -------------------------------------------------------------------------
    # 3. DATABASE & MULTI-TENANT USER ISOLATION
    # -------------------------------------------------------------------------
    def test_user_data_isolation(self):
        """Verify User 1 cannot access User 2's alerts or patch them."""
        # Create alert for User 2
        alert_u2 = SecurityAlert(
            user_id=self.user2.id,
            alert_type="message_scam",
            title="Private Threat User 2",
            message="Sensitive message detail User 2",
            severity="HIGH",
            is_read=False
        )
        self.db.add(alert_u2)
        self.db.commit()
        self.db.refresh(alert_u2)

        headers_u1 = {"Authorization": f"Bearer {self.token_user1}"}

        # User 1 queries alerts
        res_alerts = client.get("/security/alerts", headers=headers_u1)
        assert res_alerts.status_code == 200
        u1_alert_ids = [a["id"] for a in res_alerts.json()]
        assert alert_u2.id not in u1_alert_ids

        # User 1 attempts to mark User 2's alert as read -> HTTP 404
        res_patch = client.patch(f"/security/alerts/{alert_u2.id}/read", headers=headers_u1)
        assert res_patch.status_code == 404

    # -------------------------------------------------------------------------
    # 4. SECURITY SCANNER INTEGRATION & UNSCANNABLE VERDICT GUARANTEES
    # -------------------------------------------------------------------------
    def test_no_outbound_network_requests_during_url_scan(self, monkeypatch):
        """Verify URL scanner executes locally without making outbound network calls (SSRF safety)."""
        orig_connect = socket.socket.connect

        def mock_connect(self_sock, address):
            host = address[0] if isinstance(address, tuple) and len(address) > 0 else ""
            if host not in ("127.0.0.1", "localhost", "::1"):
                pytest.fail(f"Outbound network request attempted to host ({host}) during URL scan!")
            return orig_connect(self_sock, address)

        monkeypatch.setattr(socket.socket, "connect", mock_connect)

        headers_u1 = {"Authorization": f"Bearer {self.token_user1}"}
        res = client.post(
            "/security/analyze-link",
            json={"url": "http://phishing-banking-portal-scam.test/login"},
            headers=headers_u1
        )
        assert res.status_code == 200
        assert res.json()["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH RISK")

    def test_unscannable_documents_never_marked_safe(self):
        """Verify empty, corrupted, or unsupported files return UNSCANNABLE, never SAFE."""
        headers_u1 = {"Authorization": f"Bearer {self.token_user1}"}

        # 1. Empty TXT File
        r_empty = client.post(
            "/security/analyze-document",
            files={"file": ("empty.txt", b"", "text/plain")},
            headers=headers_u1
        )
        assert r_empty.status_code == 200
        assert r_empty.json()["risk_level"] == "UNSCANNABLE"

        # 2. Corrupted PDF File
        r_corrupt = client.post(
            "/security/analyze-document",
            files={"file": ("corrupt.pdf", b"%PDF-1.4 corrupted header garbage bytes", "application/pdf")},
            headers=headers_u1
        )
        assert r_corrupt.status_code == 200
        assert r_corrupt.json()["risk_level"] in ("UNSCANNABLE", "UNKNOWN")

        # 3. Unsupported File Extension (.exe binary payload)
        r_unsupported = client.post(
            "/security/analyze-document",
            files={"file": ("malware.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/octet-stream")},
            headers=headers_u1
        )
        assert r_unsupported.status_code == 200
        assert r_unsupported.json()["risk_level"] == "UNSCANNABLE"

    def test_oversized_file_rejection(self):
        """Verify file uploads exceeding 10MB limit are rejected with HTTP 400."""
        headers_u1 = {"Authorization": f"Bearer {self.token_user1}"}
        large_payload = b"X" * (10 * 1024 * 1024 + 1024)
        res = client.post(
            "/security/analyze-document",
            files={"file": ("oversized.pdf", large_payload, "application/pdf")},
            headers=headers_u1
        )
        assert res.status_code == 400
        assert "exceeds" in res.json()["detail"].lower()

    def test_guardian_alerts_feed_privacy_protection(self):
        """Verify guardian alert feeds do not expose raw message strings or passwords."""
        headers_u1 = {"Authorization": f"Bearer {self.token_user1}"}
        headers_g = {"Authorization": f"Bearer {self.token_guardian}"}

        # User 1 scans a high-risk scam message containing private OTP text
        scam_msg = "URGENT! Bank account suspended. Private OTP: 987654. Verify at http://fake-bank-login.com"
        r_scan = client.post(
            "/security/analyze-message",
            json={"message": scam_msg},
            headers=headers_u1
        )
        assert r_scan.status_code == 200
        assert r_scan.json()["risk_level"] == "HIGH RISK"

        # Guardian queries guardian alerts endpoint
        r_g_alerts = client.get("/guardian/alerts", headers=headers_g)
        assert r_g_alerts.status_code == 200
        
        # Verify response contains high-level title/guidance but NO raw message/OTP string
        for alert in r_g_alerts.json():
            alert_msg = alert.get("message", "")
            assert "987654" not in alert_msg, "Private OTP leaked in guardian alert feed!"

    # -------------------------------------------------------------------------
    # 5. DATA LEAKAGE & SENSITIVE RESPONSE SANITIZATION
    # -------------------------------------------------------------------------
    def test_no_sensitive_credential_leakage_in_api_responses(self):
        """Verify user endpoints do not leak password hashes or JWT secrets."""
        headers_u1 = {"Authorization": f"Bearer {self.token_user1}"}
        res = client.get("/users/me", headers=headers_u1)
        assert res.status_code == 200
        data = res.json()
        assert "password" not in data
        assert "password_hash" not in data
        assert "jwt_secret" not in data
