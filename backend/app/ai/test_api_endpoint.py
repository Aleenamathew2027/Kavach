"""
End-to-End Test for POST /security/analyze-message using FastAPI TestClient
Tests the exact 5 scenarios specified in Phase 5.
"""
import sys
import os

from fastapi.testclient import TestClient
from main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.utils.security import create_access_token

client = TestClient(app)

def run_phase5_api_tests():
    db = SessionLocal()
    user = db.query(User).filter(User.role == "user").first()
    db.close()
    
    if not user:
        print("ERROR: No test user found in database.")
        sys.exit(1)
        
    token = create_access_token(data={"sub": str(user.id), "role": user.role})
    headers = {"Authorization": f"Bearer {token}"}
    
    test_messages = [
        ("TEST 1 — SAFE", "Hey Mom, I will be home by 7 PM."),
        ("TEST 2 — BANK PHISHING", "URGENT! Your bank account is blocked. Click http://fake-bank.com immediately to verify your KYC."),
        ("TEST 3 — PRIZE SCAM", "Congratulations! You won Rs 50,000. Click this link immediately to claim your prize."),
        ("TEST 4 — NORMAL CONVERSATION", "Are you coming to college tomorrow?"),
        ("TEST 5 — URGENT PAYMENT", "Your electricity bill is overdue. Pay immediately at http://fake-payment.com or your service will be disconnected.")
    ]
    
    print("================================================================================")
    print("        KAVACH FASTAPI ENDPOINT TEST: POST /security/analyze-message            ")
    print("================================================================================\n")
    
    all_passed = True
    for title, msg in test_messages:
        resp = client.post("/security/analyze-message", json={"message": msg}, headers=headers)
        if resp.status_code != 200:
            print(f"FAILED for '{title}': Status {resp.status_code}, Body: {resp.text}")
            all_passed = False
            continue
            
        data = resp.json()
        print(f"[{title}]")
        print(f"  Input Message    : \"{msg}\"")
        print(f"  HTTP Status      : {resp.status_code} OK")
        print(f"  Classification   : {data.get('classification')}")
        print(f"  Final Risk Level : {data.get('risk_level')}")
        print(f"  Risk Score       : {data.get('risk_score')}/100")
        print(f"  ML Prediction    : {data.get('ml_prediction')}")
        print(f"  ML Confidence    : {data.get('ml_confidence')}%")
        print(f"  Scam Probability : {data.get('scam_probability')}%")
        print(f"  Safe Probability : {data.get('safe_probability')}%")
        print(f"  ML Model         : {data.get('model')}")
        print(f"  Summary          : {data.get('summary')}")
        print(f"  Rule Flags       : {data.get('rule_flags')}")
        print(f"  Alert Created    : {data.get('alert_created')}")
        print("-" * 80)
        
    print("\nALL 5 PHASE 5 TESTS COMPLETED SUCCESSFULLY!" if all_passed else "\nSOME TESTS FAILED!")

if __name__ == "__main__":
    run_phase5_api_tests()
