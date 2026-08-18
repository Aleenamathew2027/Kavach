"""
KAVACH — Google OAuth & ID Token Verification Service
Verifies Google Identity credentials using official Google authentication mechanisms.
"""
import logging
import os
from typing import Any, Dict, Optional
from dotenv import load_dotenv
import httpx

load_dotenv()
logger = logging.getLogger("kavach.auth.google")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()


def verify_google_token(credential: str) -> Dict[str, Any]:
    """
    Verifies a Google ID Token / Credential using Google's official verification libraries.
    
    Returns:
        dict with:
            - google_id (str): Google subject ID
            - email (str): Normalized verified email address
            - email_verified (bool): Whether the email is verified by Google
            - name (str): User's full name from Google profile
            - picture (str, optional): User's Google avatar URL
    
    Raises:
        ValueError if the token is invalid, expired, or unverified.
    """
    if not credential or not isinstance(credential, str):
        raise ValueError("Google authentication credential is required.")

    id_info = None
    verification_error = None

    # 1. Primary: Verify using official google-auth library
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token

        # If GOOGLE_CLIENT_ID is configured, enforce audience check; otherwise verify signature with Google certs
        audience = GOOGLE_CLIENT_ID if GOOGLE_CLIENT_ID else None
        request = google_requests.Request()
        id_info = google_id_token.verify_oauth2_token(
            credential,
            request,
            audience=audience,
            clock_skew_in_seconds=10
        )
    except Exception as e:
        verification_error = e
        logger.warning(f"google_id_token verification notice: {e}. Trying fallback tokeninfo check...")

    # 2. Secondary / Fallback: Verify via Google's tokeninfo endpoint (OpenID Connect specification)
    if id_info is None:
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(
                    "https://oauth2.googleapis.com/tokeninfo",
                    params={"id_token": credential}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Check audience if GOOGLE_CLIENT_ID is set
                    if GOOGLE_CLIENT_ID and data.get("aud") != GOOGLE_CLIENT_ID:
                        raise ValueError("Token audience mismatch.")
                    id_info = data
                else:
                    raise ValueError(f"Google token verification failed: {resp.text}")
        except Exception as fallback_err:
            logger.error(f"Google token verification failed completely: {fallback_err}")
            raise ValueError(f"Invalid or expired Google authentication token: {verification_error or fallback_err}")

    # 3. Extract and validate required claims
    google_id = id_info.get("sub")
    email = id_info.get("email")
    raw_verified = id_info.get("email_verified")
    email_verified = (raw_verified is True) or (str(raw_verified).lower() == "true")
    name = id_info.get("name") or (email.split("@")[0] if email else "Google User")
    picture = id_info.get("picture")

    if not google_id:
        raise ValueError("Google identity missing unique subject ID (sub).")

    if not email:
        raise ValueError("Google identity missing email address.")

    if not email_verified:
        raise ValueError("Google email address is not verified by Google.")

    return {
        "google_id": str(google_id),
        "email": email.lower().strip(),
        "email_verified": True,
        "name": name.strip(),
        "picture": picture,
    }
