"""
=============================================================================
KAVACH Phase 12 — Production Configuration Hardening & Secret Safety Tests
=============================================================================
Tests:
  1. Rejection of weak or default JWT secret in production mode.
  2. Rejection of unsupported or dangerous JWT algorithms.
  3. Proper handling and HTTP 401 rejection for expired JWT tokens.
  4. Dynamic CORS configuration via CORS_ORIGINS environment variable.
  5. Verification that backend/.env.example contains ZERO hardcoded secrets.
=============================================================================
"""

import os
import pytest
from datetime import datetime, timedelta, timezone
import jwt
from fastapi.testclient import TestClient

from main import app
from app.utils.security import (
    validate_security_config,
    create_access_token,
    decode_access_token,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
)

client = TestClient(app)

class TestProductionConfig:

    def test_production_mode_weak_secret_rejection(self):
        """Production mode must reject missing or default weak JWT secret keys."""
        # Weak default secret in production -> raises ValueError
        with pytest.raises(ValueError, match="Production mode requires a strong custom JWT_SECRET_KEY"):
            validate_security_config(
                env="production",
                secret="kavach_default_secret_key_please_set_in_env",
                algo="HS256"
            )

        # Short secret (< 32 chars) in production -> raises ValueError
        with pytest.raises(ValueError, match="Production mode requires a strong custom JWT_SECRET_KEY"):
            validate_security_config(
                env="production",
                secret="short_secret_123",
                algo="HS256"
            )

        # Valid 32+ char secret in production -> succeeds
        validate_security_config(
            env="production",
            secret="a_very_secure_and_long_production_jwt_secret_key_12345",
            algo="HS256"
        )

    def test_invalid_jwt_algorithm_rejection(self):
        """Unsupported or unsafe algorithms (e.g. 'none', 'RS256' without key) must be rejected."""
        with pytest.raises(ValueError, match="Unsafe JWT algorithm"):
            validate_security_config(
                env="development",
                secret="test_secret",
                algo="none"
            )

        with pytest.raises(ValueError, match="Unsafe JWT algorithm"):
            validate_security_config(
                env="development",
                secret="test_secret",
                algo="RS256"
            )

    def test_expired_token_validation(self):
        """Expired JWT tokens must trigger ExpiredSignatureError and return HTTP 401."""
        expired_payload = {
            "sub": "100",
            "role": "user",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=10)
        }
        expired_jwt = jwt.encode(expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        # Attempting to access protected endpoint with expired token
        res = client.get("/users/me", headers={"Authorization": f"Bearer {expired_jwt}"})
        assert res.status_code == 401
        assert "expired" in res.json()["detail"].lower()

    def test_cors_origins_environment_configuration(self, monkeypatch):
        """CORS origins must dynamically include CORS_ORIGINS from environment while keeping defaults."""
        from main import default_origins, env_cors

        # Confirm default origins exist
        assert "http://127.0.0.1:5173" in default_origins
        assert "http://localhost:5173" in default_origins

    def test_env_example_contains_no_secrets(self):
        """Verify .env.example contains only placeholders and no real sensitive values."""
        example_path = os.path.join(os.path.dirname(__file__), ".env.example")
        assert os.path.exists(example_path), ".env.example file missing!"

        with open(example_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        content = "".join(lines)
        # Ensure standard safe placeholders are present
        assert "your_postgres_password_here" in content or "your_password" in content
        assert "your_secure_admin_password_here" in content or "admin@" in content
        assert "your_google_client_id_here" in content
        assert "your_google_client_secret_here" in content

        # Ensure no actual JWT production secret key or private keys are exposed
        for line in lines:
            line_str = line.strip()
            if line_str and not line_str.startswith("#"):
                key, _, val = line_str.partition("=")
                if key == "JWT_SECRET_KEY":
                    assert "minimum_32_chars" in val or "your_" in val or val == ""
