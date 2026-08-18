"""
KAVACH — Google Authentication, Account Linking & Role Security Test Suite
"""
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.guardian import GuardianAccess
from app.utils.security import hash_password

client = TestClient(app)

def run_tests():
    print("================================================================================")
    print("               KAVACH — GOOGLE AUTHENTICATION & SECURITY TEST                   ")
    print("================================================================================\n", flush=True)
    
    all_passed = True
    
    # ── 1. TEST 1: Existing Email/Password User Login ──
    print("[TEST 1] Email/Password User Login:", flush=True)
    test_user_email = "testuser_local@kavach.sec"
    
    db = SessionLocal()
    try:
        local_user = db.query(User).filter(User.email == test_user_email).first()
        if not local_user:
            local_user = User(
                full_name="Local Test User",
                email=test_user_email,
                password=hash_password("Password123!"),
                role="user",
                auth_provider="local"
            )
            db.add(local_user)
            db.commit()
            db.refresh(local_user)
        local_user_id = local_user.id
    finally:
        db.close()
    
    resp1 = client.post("/users/login", json={"email": test_user_email, "password": "Password123!"})
    print(f"  POST /users/login -> Status: {resp1.status_code}, Role: {resp1.json().get('role')}", flush=True)
    if resp1.status_code != 200 or resp1.json().get("role") != "user":
        all_passed = False

    # ── 2. TEST 2: New Google User Registration ──
    print("\n[TEST 2] New Google User Registration via verified token:", flush=True)
    mock_google_new = {
        "google_id": "google_sub_9876543210",
        "email": "new_google_user@gmail.com",
        "email_verified": True,
        "name": "Aarav Sharma",
        "picture": "https://lh3.googleusercontent.com/a/mock-pic"
    }
    
    # Clean up if already exists from earlier run
    db = SessionLocal()
    try:
        existing_g = db.query(User).filter(User.email == mock_google_new["email"]).first()
        if existing_g:
            db.delete(existing_g)
            db.commit()
    finally:
        db.close()
    
    with patch("app.api.user.verify_google_token", return_value=mock_google_new):
        resp2 = client.post("/users/google-login", json={"credential": "mock_google_id_token_xyz"})
        print(f"  POST /users/google-login -> Status: {resp2.status_code}, Role: {resp2.json().get('role')}", flush=True)
        token_data = resp2.json()
        google_jwt = token_data.get("access_token")
        
        # Verify in DB
        db = SessionLocal()
        try:
            created_user = db.query(User).filter(User.email == mock_google_new["email"]).first()
            print(f"  DB Check: ID={created_user.id}, Role={created_user.role}, Provider={created_user.auth_provider}, GoogleID={created_user.google_id}", flush=True)
            if resp2.status_code != 200 or created_user.role != "user" or created_user.auth_provider != "google":
                all_passed = False
        finally:
            db.close()

    # ── 3. TEST 3: Existing Google User Login (No Duplicates) ──
    print("\n[TEST 3] Existing Google User Login:", flush=True)
    db = SessionLocal()
    count_before = db.query(User).filter(User.email == mock_google_new["email"]).count()
    db.close()
    
    with patch("app.api.user.verify_google_token", return_value=mock_google_new):
        resp3 = client.post("/users/google-login", json={"credential": "mock_google_id_token_xyz"})
        db = SessionLocal()
        count_after = db.query(User).filter(User.email == mock_google_new["email"]).count()
        db.close()
        print(f"  POST /users/google-login -> Status: {resp3.status_code}, Duplicate count check: {count_before} == {count_after}", flush=True)
        if resp3.status_code != 200 or count_before != count_after:
            all_passed = False

    # ── 4. TEST 4: Google User Accesses /user/dashboard ──
    print("\n[TEST 4] Google User Accesses /user/dashboard:", flush=True)
    user_headers = {"Authorization": f"Bearer {google_jwt}"}
    resp4 = client.get("/user/dashboard", headers=user_headers)
    print(f"  GET /user/dashboard -> Status: {resp4.status_code} (Expected 200)", flush=True)
    if resp4.status_code != 200:
        all_passed = False

    # ── 5. TEST 5: Google User Accesses /admin/dashboard (Forbidden) ──
    print("\n[TEST 5] Google User Attempts /admin/dashboard:", flush=True)
    resp5 = client.get("/admin/dashboard", headers=user_headers)
    print(f"  GET /admin/dashboard -> Status: {resp5.status_code} (Expected 403 Forbidden)", flush=True)
    if resp5.status_code != 403:
        all_passed = False

    # ── 6. TEST 6: Google User Accesses /guardian/dashboard (Forbidden) ──
    print("\n[TEST 6] Google User Attempts /guardian/dashboard:", flush=True)
    resp6 = client.get("/guardian/dashboard", headers=user_headers)
    print(f"  GET /guardian/dashboard -> Status: {resp6.status_code} (Expected 403 Forbidden)", flush=True)
    if resp6.status_code != 403:
        all_passed = False

    # ── 7. TEST 7: Admin Security Protection from Google Bypass ──
    print("\n[TEST 7] Google Login Attempt with Admin Email:", flush=True)
    mock_google_admin = {
        "google_id": "google_sub_admin_attacker",
        "email": "admin@kavach.com",
        "email_verified": True,
        "name": "Admin Attacker",
        "picture": None
    }
    with patch("app.api.user.verify_google_token", return_value=mock_google_admin):
        resp7 = client.post("/users/google-login", json={"credential": "mock_admin_google_token"})
        print(f"  POST /users/google-login with admin email -> Status: {resp7.status_code} (Expected 403 Forbidden)", flush=True)
        if resp7.status_code != 403:
            all_passed = False

    # ── 8. TEST 8: Existing User Account Linking via Google ──
    print("\n[TEST 8] Existing Local User Links Google Account:", flush=True)
    link_email = "link_candidate@kavach.sec"
    db = SessionLocal()
    try:
        link_user = db.query(User).filter(User.email == link_email).first()
        if not link_user:
            link_user = User(
                full_name="Link Candidate",
                email=link_email,
                password=hash_password("SafePassword123!"),
                role="user",
                auth_provider="local"
            )
            db.add(link_user)
            db.commit()
    finally:
        db.close()

    mock_google_link = {
        "google_id": "google_sub_linked_5555",
        "email": link_email,
        "email_verified": True,
        "name": "Link Candidate",
        "picture": None
    }
    with patch("app.api.user.verify_google_token", return_value=mock_google_link):
        resp8 = client.post("/users/google-login", json={"credential": "mock_link_token"})
        db = SessionLocal()
        try:
            refreshed_user = db.query(User).filter(User.email == link_email).first()
            print(f"  POST /users/google-login -> Status: {resp8.status_code}, User google_id={refreshed_user.google_id}, Provider={refreshed_user.auth_provider}", flush=True)
            if resp8.status_code != 200 or refreshed_user.google_id != "google_sub_linked_5555":
                all_passed = False
        finally:
            db.close()

    # ── 9. TEST 9: Existing Admin Password Login ──
    print("\n[TEST 9] Existing Admin Password Login:", flush=True)
    resp9 = client.post("/users/login", json={"email": "admin@kavach.com", "password": "KavachAdmin@123"})
    print(f"  POST /users/login -> Status: {resp9.status_code}, Role: {resp9.json().get('role')}", flush=True)
    if resp9.status_code != 200 or resp9.json().get("role") != "admin":
        all_passed = False

    # ── 10. TEST 10: Guardian 6-Digit Code Authentication ──
    print("\n[TEST 10] Guardian 6-Digit Code Verification:", flush=True)
    now = datetime.now(timezone.utc)
    g_code = "876543"
    db = SessionLocal()
    try:
        g_access = GuardianAccess(
            user_id=local_user_id,
            code_hash=hash_password(g_code),
            is_active=True,
            expires_at=now + timedelta(hours=2)
        )
        db.add(g_access)
        db.commit()
    finally:
        db.close()

    resp10 = client.post("/guardian/verify-code", json={"code": g_code})
    print(f"  POST /guardian/verify-code -> Status: {resp10.status_code}, Role: {resp10.json().get('role')}", flush=True)
    if resp10.status_code != 200 or resp10.json().get("role") != "guardian":
        all_passed = False

    # ── 11. Database Inspection Output ──
    print("\n[TEST 11] PostgreSQL Database State (Safe projection):", flush=True)
    db = SessionLocal()
    try:
        users = db.query(User.id, User.full_name, User.email, User.role, User.auth_provider, User.google_id).order_by(User.id).all()
        print(f"{'ID':<4} | {'Full Name':<20} | {'Email':<28} | {'Role':<8} | {'Provider':<8} | {'Google ID'}", flush=True)
        print("-" * 90, flush=True)
        for u in users:
            gid = u.google_id if u.google_id else "None"
            print(f"{u.id:<4} | {u.full_name:<20} | {u.email:<28} | {u.role:<8} | {u.auth_provider:<8} | {gid}", flush=True)
    finally:
        db.close()
    
    print("\n" + ("=" * 80), flush=True)
    if all_passed:
        print("           ALL GOOGLE AUTHENTICATION & SECURITY TESTS PASSED 100%!       ", flush=True)
    else:
        print("           SOME TESTS FAILED! PLEASE CHECK THE LOGS ABOVE.             ", flush=True)
    print("=" * 80, flush=True)

if __name__ == "__main__":
    run_tests()
