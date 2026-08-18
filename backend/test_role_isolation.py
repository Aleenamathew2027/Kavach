"""
Comprehensive Verification Test for KAVACH Role Isolation and Dashboard Endpoints
Tests User, Guardian, and Admin roles and verifies strict route access control.
"""
from fastapi.testclient import TestClient
from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.guardian import GuardianAccess
from app.utils.security import create_access_token
import sys

client = TestClient(app)

def run_role_isolation_tests():
    db = SessionLocal()
    
    # 1. Fetch Users by role
    user_acc = db.query(User).filter(User.role == "user").first()
    admin_acc = db.query(User).filter(User.role == "admin").first()
    guardian_link = db.query(GuardianAccess).filter(GuardianAccess.is_active == True).first()
    
    if not user_acc or not admin_acc:
        print("ERROR: Test user or admin not found in DB.")
        db.close()
        sys.exit(1)
        
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    
    # Create or refresh active guardian link
    guardian_link = db.query(GuardianAccess).filter(
        GuardianAccess.user_id == user_acc.id,
        GuardianAccess.is_active == True,
        GuardianAccess.expires_at > now
    ).first()
    
    if not guardian_link:
        guardian_link = GuardianAccess(
            user_id=user_acc.id,
            code_hash="test_code_hash",
            is_active=True,
            expires_at=now + timedelta(hours=24)
        )
        db.add(guardian_link)
        db.commit()
        db.refresh(guardian_link)
        
    user_token = create_access_token(data={"sub": str(user_acc.id), "role": "user"})
    admin_token = create_access_token(data={"sub": str(admin_acc.id), "role": "admin"})
    guardian_token = create_access_token(data={
        "sub": str(user_acc.id),
        "role": "guardian",
        "guardian_access_id": guardian_link.id
    })
    
    db.close()
    
    user_headers = {"Authorization": f"Bearer {user_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    guardian_headers = {"Authorization": f"Bearer {guardian_token}"}
    
    print("================================================================================")
    print("                KAVACH ROLE ISOLATION & API ENDPOINTS TEST                      ")
    print("================================================================================\n")
    
    all_ok = True
    
    # --- 1. USER ENDPOINTS TEST ---
    print("[1] TESTING USER ACCESS:")
    r1 = client.get("/user/dashboard", headers=user_headers)
    print(f"  GET /user/dashboard with User Token        -> {r1.status_code} (Expected 200)")
    if r1.status_code != 200: all_ok = False
    
    r2 = client.post("/security/analyze-message", json={"message": "URGENT! Bank blocked. Click http://fake-bank.com"}, headers=user_headers)
    print(f"  POST /security/analyze-message with ML -> {r2.status_code} (Classification: {r2.json().get('classification')}, ML: {r2.json().get('model')})")
    if r2.status_code != 200: all_ok = False
    
    r3 = client.get("/security/alerts", headers=user_headers)
    print(f"  GET /security/alerts with User Token       -> {r3.status_code} (Alerts Count: {len(r3.json())})")
    if r3.status_code != 200: all_ok = False
    
    # Role Isolation: User cannot access Admin or Guardian endpoints
    r4 = client.get("/admin/dashboard", headers=user_headers)
    print(f"  GET /admin/dashboard with User Token       -> {r4.status_code} (Expected 403 Forbidden)")
    if r4.status_code != 403: all_ok = False
    
    r5 = client.get("/guardian/dashboard", headers=user_headers)
    print(f"  GET /guardian/dashboard with User Token    -> {r5.status_code} (Expected 403 Forbidden)")
    if r5.status_code != 403: all_ok = False
    
    # --- 2. GUARDIAN ENDPOINTS TEST ---
    print("\n[2] TESTING GUARDIAN ACCESS:")
    g1 = client.get("/guardian/dashboard", headers=guardian_headers)
    print(f"  GET /guardian/dashboard with Guardian Token-> {g1.status_code} (Protected: {g1.json().get('guarded_user', {}).get('full_name')})")
    if g1.status_code != 200: all_ok = False
    
    g2 = client.get("/guardian/alerts", headers=guardian_headers)
    print(f"  GET /guardian/alerts with Guardian Token   -> {g2.status_code} (Alerts: {len(g2.json())})")
    if g2.status_code != 200: all_ok = False
    
    g3 = client.get("/guardian/activity", headers=guardian_headers)
    print(f"  GET /guardian/activity with Guardian Token -> {g3.status_code} (Activity items: {len(g3.json())})")
    if g3.status_code != 200: all_ok = False
    
    # Role Isolation: Guardian cannot access Admin or User endpoints
    g4 = client.get("/admin/dashboard", headers=guardian_headers)
    print(f"  GET /admin/dashboard with Guardian Token   -> {g4.status_code} (Expected 403 Forbidden)")
    if g4.status_code != 403: all_ok = False
    
    g5 = client.get("/user/dashboard", headers=guardian_headers)
    print(f"  GET /user/dashboard with Guardian Token    -> {g5.status_code} (Expected 403 Forbidden)")
    if g5.status_code != 403: all_ok = False
    
    # --- 3. ADMIN ENDPOINTS TEST ---
    print("\n[3] TESTING ADMIN ACCESS:")
    a1 = client.get("/admin/dashboard", headers=admin_headers)
    print(f"  GET /admin/dashboard with Admin Token      -> {a1.status_code} (Total Users: {a1.json().get('total_users')}, Total Scans: {a1.json().get('total_scans')})")
    if a1.status_code != 200: all_ok = False
    
    a2 = client.get("/admin/users", headers=admin_headers)
    print(f"  GET /admin/users with Admin Token          -> {a2.status_code} (Users Count: {len(a2.json())})")
    if a2.status_code != 200: all_ok = False
    
    a3 = client.get("/admin/security-events", headers=admin_headers)
    print(f"  GET /admin/security-events with Admin Token-> {a3.status_code} (Events Count: {len(a3.json())})")
    if a3.status_code != 200: all_ok = False
    
    a4 = client.get("/admin/guardians", headers=admin_headers)
    print(f"  GET /admin/guardians with Admin Token      -> {a4.status_code} (Guardian Links: {len(a4.json())})")
    if a4.status_code != 200: all_ok = False
    
    a5 = client.get("/admin/reports", headers=admin_headers)
    print(f"  GET /admin/reports with Admin Token        -> {a5.status_code} (Safety Rate: {a5.json().get('safety_rate')}%)")
    if a5.status_code != 200: all_ok = False
    
    a6 = client.get("/admin/activity", headers=admin_headers)
    print(f"  GET /admin/activity with Admin Token       -> {a6.status_code} (Audit items: {len(a6.json())})")
    if a6.status_code != 200: all_ok = False
    
    # Role Isolation: Admin cannot access Guardian endpoints
    a7 = client.get("/guardian/dashboard", headers=admin_headers)
    print(f"  GET /guardian/dashboard with Admin Token   -> {a7.status_code} (Expected 403 Forbidden)")
    if a7.status_code != 403: all_ok = False
    
    print("\n" + ("=" * 80))
    print("             ALL ROLE ISOLATION & API TESTS PASSED 100%!                " if all_ok else "             SOME TESTS FAILED!                ")
    print("=" * 80)

if __name__ == "__main__":
    run_role_isolation_tests()
