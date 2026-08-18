import os
import joblib
from app.ai.message_detector import MessageScamDetector, predict_message_scam

test_msgs = [
    ("TEST 1 - SAFE", "Hey Mom, I will be home by 7 PM."),
    ("TEST 2 - BANK PHISHING", "URGENT! Your bank account is blocked. Click http://fake-bank.com immediately to verify your KYC."),
    ("TEST 3 - PRIZE SCAM", "Congratulations! You won Rs 50,000. Click this link immediately to claim your prize."),
    ("TEST 4 - NORMAL CONVERSATION", "Are you coming to college tomorrow?"),
    ("TEST 5 - URGENT PAYMENT", "Your electricity bill is overdue. Pay immediately at http://fake-payment.com or your service will be disconnected.")
]

print("=== VERIFICATION OF ML INFERENCE SERVICE ===\n")
for label, text in test_msgs:
    res = predict_message_scam(text)
    print(f"{label}:")
    print(f"  Input text      : \"{text}\"")
    print(f"  Cleaned text    : \"{res['cleaned_text']}\"")
    print(f"  ML Prediction   : [{res['prediction']}]")
    print(f"  Confidence      : {res['confidence']*100:.2f}%")
    print(f"  Scam Probability: {res['scam_probability']*100:.2f}%")
    print(f"  Safe Probability: {res['safe_probability']*100:.2f}%")
    print("-" * 75)
