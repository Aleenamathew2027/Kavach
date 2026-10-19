import os
import secrets
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import jwt

from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.guardian import GuardianAccess

client = TestClient(app)

print("=" * 60)
print("RUNNING COMPLETE KAVACH RBAC & AUTHENTICATION TEST SUITE")
print("=" * 60)

test_id = secrets.token_hex(4)
user_email = f"test_rbac_user_{test_id}@kavach.ai"
user_pwd = "KavachUserPassword123"
user_name = "Aleena Mathew"

# 1. Normal user registration
res = client.post("/users/register", json={"full_name": user_name, "email": user_email, "password": user_pwd})
assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
user_id = res.json()["id"]
print(f"1. Normal user registration: SUCCESS (User ID {user_id})")

# 2. Name containing numbers -> rejected
res = client.post("/users/register", json={"full_name": "Aleena123", "email": f"bad_name1_{test_id}@test.com", "password": user_pwd})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("2. Name containing numbers -> rejected: SUCCESS (422)")

# 3. Name containing @ -> rejected
res = client.post("/users/register", json={"full_name": "Aleena@Mathew", "email": f"bad_name2_{test_id}@test.com", "password": user_pwd})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("3. Name containing @ -> rejected: SUCCESS (422)")

# 4. Name containing # -> rejected
res = client.post("/users/register", json={"full_name": "Aleena#Mathew", "email": f"bad_name3_{test_id}@test.com", "password": user_pwd})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("4. Name containing # -> rejected: SUCCESS (422)")

# 5. Name containing $ -> rejected
res = client.post("/users/register", json={"full_name": "Aleena$Mathew", "email": f"bad_name4_{test_id}@test.com", "password": user_pwd})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("5. Name containing $ -> rejected: SUCCESS (422)")

# 6. Invalid email -> rejected
res = client.post("/users/register", json={"full_name": "Valid Name", "email": "invalid_email_format", "password": user_pwd})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("6. Invalid email -> rejected: SUCCESS (422)")

# 7. Weak password (length < 6) -> rejected
res = client.post("/users/register", json={"full_name": "Valid Name", "email": f"valid_{test_id}@test.com", "password": "123"})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("7. Weak password -> rejected: SUCCESS (422)")

# 8. Duplicate email -> rejected
res = client.post("/users/register", json={"full_name": "Another Name", "email": user_email, "password": user_pwd})
assert res.status_code == 400, f"Expected 400, got {res.status_code}: {res.text}"
print("8. Duplicate email -> rejected: SUCCESS (400)")

# 9. Normal user login
res = client.post("/users/login", json={"email": user_email, "password": user_pwd})
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
user_token = res.json()["access_token"]
user_role = res.json()["role"]
assert user_role == "user", f"Expected role user, got {user_role}"
print(f"9. Normal user login: SUCCESS (Received token with role '{user_role}')")

# 10. Wrong user password -> rejected
res = client.post("/users/login", json={"email": user_email, "password": "WrongPassword123"})
assert res.status_code == 401, f"Expected 401, got {res.status_code}"
print("10. Wrong user password -> rejected: SUCCESS (401)")

# 11. Admin login with correct credentials
admin_email = os.getenv("ADMIN_EMAIL", "admin@kavach.com")
admin_pwd = os.getenv("ADMIN_PASSWORD", "KavachAdmin@123")
res = client.post("/users/login", json={"email": admin_email, "password": admin_pwd})
assert res.status_code == 200, f"Expected 200 for admin login, got {res.status_code}: {res.text}"
admin_token = res.json()["access_token"]
admin_role = res.json()["role"]
assert admin_role == "admin", f"Expected role admin, got {admin_role}"
print(f"11. Admin login with correct credentials: SUCCESS (Received token with role '{admin_role}')")

# 12. Admin login with wrong credentials -> rejected
res = client.post("/users/login", json={"email": admin_email, "password": "WrongAdminPassword"})
assert res.status_code == 401, f"Expected 401, got {res.status_code}"
print("12. Admin login with wrong credentials -> rejected: SUCCESS (401)")

# 13. User receives role=user
assert user_role == "user"
print("13. User receives role=user: SUCCESS")

# 14. Admin receives role=admin
assert admin_role == "admin"
print("14. Admin receives role=admin: SUCCESS")

# 15. User cannot access admin dashboard -> 403
res = client.get("/admin/dashboard", headers={"Authorization": f"Bearer {user_token}"})
assert res.status_code == 403, f"Expected 403, got {res.status_code}"
print("15. User cannot access admin dashboard: SUCCESS (403 Forbidden)")

# 16. User cannot access guardian dashboard -> 403
res = client.get("/guardian/dashboard", headers={"Authorization": f"Bearer {user_token}"})
assert res.status_code == 403, f"Expected 403, got {res.status_code}"
print("16. User cannot access guardian dashboard: SUCCESS (403 Forbidden)")

# 17. User generates 6-digit guardian access code
res = client.post("/guardian/generate-code", headers={"Authorization": f"Bearer {user_token}"})
assert res.status_code in (200, 201), f"Expected 200 or 201, got {res.status_code}"
guardian_code = res.json()["code"]
assert len(guardian_code) == 6 and guardian_code.isdigit(), f"Invalid code: {guardian_code}"
print(f"17. User generates 6-digit guardian code: SUCCESS")

# 18. Invalid guardian code -> rejected
res = client.post("/guardian/verify-code", json={"code": "000000"})
assert res.status_code == 401, f"Expected 401, got {res.status_code}"
print("18. Invalid guardian code -> rejected: SUCCESS (401)")

# 19. Guardian code with letters -> rejected
res = client.post("/guardian/verify-code", json={"code": "12A456"})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("19. Guardian code with letters -> rejected: SUCCESS (422)")

# 20. Guardian code with less than 6 digits -> rejected
res = client.post("/guardian/verify-code", json={"code": "12345"})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("20. Guardian code with less than 6 digits -> rejected: SUCCESS (422)")

# 21. Guardian code with more than 6 digits -> rejected
res = client.post("/guardian/verify-code", json={"code": "1234567"})
assert res.status_code == 422, f"Expected 422, got {res.status_code}"
print("21. Guardian code with more than 6 digits -> rejected: SUCCESS (422)")

# 22. Valid guardian code -> guardian authentication
res = client.post("/guardian/verify-code", json={"code": guardian_code})
assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
guardian_token = res.json()["access_token"]
guardian_role = res.json()["role"]
assert guardian_role == "guardian", f"Expected role guardian, got {guardian_role}"
print(f"22. Valid guardian code -> authentication: SUCCESS (Received token with role '{guardian_role}')")

# 23. Guardian can access guardian dashboard
res = client.get("/guardian/dashboard", headers={"Authorization": f"Bearer {guardian_token}"})
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
assert res.json()["guarded_user"]["email"] == user_email
print("23. Guardian can access guardian dashboard: SUCCESS (200)")

# 24. Guardian cannot access admin dashboard -> 403
res = client.get("/admin/dashboard", headers={"Authorization": f"Bearer {guardian_token}"})
assert res.status_code == 403, f"Expected 403, got {res.status_code}"
print("24. Guardian cannot access admin dashboard: SUCCESS (403 Forbidden)")

# 25. Guardian cannot access user dashboard -> 403
res = client.get("/user/dashboard", headers={"Authorization": f"Bearer {guardian_token}"})
assert res.status_code == 403, f"Expected 403, got {res.status_code}"
print("25. Guardian cannot access user dashboard: SUCCESS (403 Forbidden)")

# 26. /users/me works with valid JWT
res = client.get("/users/me", headers={"Authorization": f"Bearer {user_token}"})
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
assert res.json()["email"] == user_email
assert res.json()["role"] == "user"
print(f"26. /users/me works with valid JWT: SUCCESS (Returned {res.json()['email']} with role '{res.json()['role']}')")

# 27. /users/me without JWT -> 401
res = client.get("/users/me")
assert res.status_code == 401, f"Expected 401, got {res.status_code}"
print("27. /users/me without JWT -> 401: SUCCESS")

# 28. Expired JWT -> 401
secret = os.getenv("JWT_SECRET_KEY", "kavach_default_secret_key_please_set_in_env")
algo = os.getenv("JWT_ALGORITHM", "HS256")
expired_payload = {"sub": str(user_id), "role": "user", "exp": datetime.now(timezone.utc) - timedelta(hours=1)}
expired_token = jwt.encode(expired_payload, secret, algorithm=algo)
res = client.get("/users/me", headers={"Authorization": f"Bearer {expired_token}"})
assert res.status_code == 401, f"Expected 401, got {res.status_code}"
print("28. Expired JWT -> 401: SUCCESS")

# Bonus: Admin can access admin dashboard
res = client.get("/admin/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
print("Bonus: Admin accesses admin dashboard: SUCCESS (200)")

# Bonus: User can access user dashboard
res = client.get("/user/dashboard", headers={"Authorization": f"Bearer {user_token}"})
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
print("Bonus: User accesses user dashboard: SUCCESS (200)")

print("=" * 60)
print("ALL 28 TESTS COMPLETED WITH 100% SUCCESS!")
print("=" * 60)
