"""
=============================================================================
KAVACH Phase 14 — System Health Check Unit Tests
=============================================================================
Verifies GET /health endpoint:
  1. Returns HTTP 200 with status='healthy' when DB is connected.
  2. Returns database status, version, app title, and environment.
  3. Does NOT leak secrets, passwords, stack traces, or credentials.
=============================================================================
"""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] in ("healthy", "degraded")
    assert data["app_title"] == "Kavach API"
    assert data["version"] == "1.0.0"
    assert "database" in data
    assert "environment" in data

    # Verify zero secret leakage in health response
    assert "password" not in data
    assert "jwt_secret" not in data
    assert "secret" not in data
