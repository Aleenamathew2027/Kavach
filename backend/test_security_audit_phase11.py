"""
=============================================================================
KAVACH Phase 11 — Security, Privacy & Production Readiness Audit Tests
=============================================================================
Tests security constraints:
  1. Unauthorized API access protection (missing/invalid JWTs)
  2. Cross-user data isolation (User A cannot access User B's alerts)
  3. Guardian privilege escalation prevention
  4. Outbound network request isolation during URL scanning (SSRF prevention)
  5. File upload size & error safety limits
=============================================================================
"""

import os
import socket
import pytest
from fastapi.testclient import TestClient

from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.security_alert import SecurityAlert
from app.utils.security import create_access_token

client = TestClient(app)

class TestSecurityAuditPhase11:

    @pytest.fixture(autouse=True)
    def setup_db(self):
        self.db = SessionLocal()
        # Seed test users
        self.user_a = self.db.query(User).filter(User.email == "sec_user_a@kavach.ai").first()
        if not self.user_a:
            self.user_a = User(
                full_name="Security User A",
                email="sec_user_a@kavach.ai",
                password="test_hash_a",
                role="user"
            )
            self.db.add(self.user_a)
            self.db.commit()
            self.db.refresh(self.user_a)

        self.user_b = self.db.query(User).filter(User.email == "sec_user_b@kavach.ai").first()
        if not self.user_b:
            self.user_b = User(
                full_name="Security User B",
                email="sec_user_b@kavach.ai",
                password="test_hash_b",
                role="user"
            )
            self.db.add(self.user_b)
            self.db.commit()
            self.db.refresh(self.user_b)

        self.token_a = create_access_token({"sub": str(self.user_a.id), "role": "user"})
        self.token_b = create_access_token({"sub": str(self.user_b.id), "role": "user"})
        
        yield
        self.db.close()

    def test_unauthorized_access_rejection(self):
        """Endpoints requiring authentication must reject requests without valid Bearer tokens."""
        # Missing token
        r1 = client.get("/security/alerts")
        assert r1.status_code == 401

        # Invalid token
        r2 = client.get("/security/alerts", headers={"Authorization": "Bearer invalid_jwt_token_payload"})
        assert r2.status_code == 401

    def test_cross_user_data_isolation(self):
        """User A should never be able to read or modify User B's security alerts."""
        # Create an alert belonging to User B
        alert_b = SecurityAlert(
            user_id=self.user_b.id,
            alert_type="message_scam",
            title="User B Private Alert",
            message="Private threat detail for User B",
            severity="HIGH",
            is_read=False
        )
        self.db.add(alert_b)
        self.db.commit()
        self.db.refresh(alert_b)

        headers_a = {"Authorization": f"Bearer {self.token_a}"}

        # User A requests their own alerts list
        r_alerts = client.get("/security/alerts", headers=headers_a)
        assert r_alerts.status_code == 200
        user_a_alert_ids = [a["id"] for a in r_alerts.json()]
        assert alert_b.id not in user_a_alert_ids

        # User A attempts to mark User B's alert as read -> HTTP 404 NOT FOUND
        r_patch = client.patch(f"/security/alerts/{alert_b.id}/read", headers=headers_a)
        assert r_patch.status_code == 404

    def test_guardian_privilege_escalation_prevention(self):
        """Guardian role tokens must be barred from accessing User/Admin endpoints."""
        guardian_token = create_access_token({
            "sub": str(self.user_a.id),
            "role": "guardian",
            "guardian_access_id": 99999
        })
        headers_g = {"Authorization": f"Bearer {guardian_token}"}

        # Cannot access user endpoints
        r_user_dash = client.get("/user/dashboard", headers=headers_g)
        assert r_user_dash.status_code == 403

        # Cannot access admin endpoints
        r_admin_dash = client.get("/admin/dashboard", headers=headers_g)
        assert r_admin_dash.status_code == 403

    def test_no_outbound_network_calls_during_link_analysis(self, monkeypatch):
        """Verify hybrid link scanner runs locally without making external outbound network calls."""
        orig_connect = socket.socket.connect

        def mock_socket_connect(self_sock, address):
            host = address[0] if isinstance(address, tuple) and len(address) > 0 else ""
            if host not in ("127.0.0.1", "localhost", "::1"):
                pytest.fail(f"Outbound network connection attempted to external host ({host}) during URL scan!")
            return orig_connect(self_sock, address)

        monkeypatch.setattr(socket.socket, "connect", mock_socket_connect)

        headers_a = {"Authorization": f"Bearer {self.token_a}"}
        res = client.post(
            "/security/analyze-link",
            json={"url": "http://suspicious-phishing-login-portal.example.com/verify"},
            headers=headers_a
        )
        assert res.status_code == 200
        assert res.json()["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH RISK")

    def test_oversized_file_upload_rejection(self):
        """File uploads exceeding 10MB limit must be rejected safely."""
        headers_a = {"Authorization": f"Bearer {self.token_a}"}
        # 10.5 MB payload
        large_bytes = b"A" * (10 * 1024 * 1024 + 500)
        res = client.post(
            "/security/analyze-document",
            files={"file": ("oversized.txt", large_bytes, "text/plain")},
            headers=headers_a
        )
        assert res.status_code == 400
        assert "exceeds" in res.json()["detail"].lower()
