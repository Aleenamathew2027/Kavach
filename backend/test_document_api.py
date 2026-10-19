"""
=============================================================================
KAVACH — Integration Test Suite for Document API Endpoint
=============================================================================
"""

import secrets
import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


@pytest.fixture(scope="module")
def auth_headers():
    test_id = secrets.token_hex(4)
    email = f"doc_api_user_{test_id}@kavach.ai"
    password = "SafePassword123!"

    # Register user
    reg_res = client.post(
        "/users/register",
        json={"full_name": "Document Tester", "email": email, "password": password}
    )
    assert reg_res.status_code == 201

    # Login to get JWT
    login_res = client.post(
        "/users/login",
        json={"email": email, "password": password}
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_analyze_document_unauthorized():
    res = client.post(
        "/security/analyze-document",
        files={"file": ("test.txt", b"Hello world", "text/plain")}
    )
    assert res.status_code in [401, 403]


def test_analyze_document_safe_file(auth_headers):
    content = b"Meeting Minutes: The team discussed the Q3 project timeline and agreed to finalize the design draft by Friday."
    res = client.post(
        "/security/analyze-document",
        headers=auth_headers,
        files={"file": ("receipt.txt", content, "text/plain")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["filename"] == "receipt.txt"
    assert data["risk_level"] == "SAFE"
    assert data["risk_score"] < 40
    assert data["scan_id"] is not None
    assert "ocr_info" in data
    assert "threat_breakdown" in data


def test_analyze_document_scam_file(auth_headers):
    content = (
        b"URGENT NOTICE: Your online banking account has been suspended! "
        b"Claim your $5,000 refund immediately by verifying your OTP and login details at "
        b"http://login-verify-account-security-update.xyz/login"
    )
    res = client.post(
        "/security/analyze-document",
        headers=auth_headers,
        files={"file": ("urgent_scam_notice.txt", content, "text/plain")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["filename"] == "urgent_scam_notice.txt"
    assert data["risk_level"] in ["HIGH RISK", "SUSPICIOUS"]
    assert data["risk_score"] >= 60
    assert data["alert_created"] is True
    assert len(data["detected_indicators"]) > 0
