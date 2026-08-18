from app.ai.message_detector import predict_message_scam

test_cases = [
    ("Normal personal message", "Hey Mom, I will be reaching home by 7:30 PM. Please keep dinner ready!"),
    ("Promotional scam", "Congratulations! You have won a prize. Click this link immediately to claim your reward."),
    ("Bank phishing", "Your bank account has been suspended. Update your KYC immediately using this link."),
    ("Normal business message", "Your appointment is confirmed for tomorrow at 10 AM."),
    ("Urgent payment scam", "URGENT! Your electricity connection will be disconnected tonight. Pay immediately.")
]

print("=== DIRECT ML INFERENCE TESTS ===\n")
for category, msg in test_cases:
    res = predict_message_scam(msg)
    print(f"Category : {category}")
    print(f"Message  : \"{msg}\"")
    print(f"Result   : Prediction=[{res['prediction']}], Confidence={res['confidence']*100:.2f}%, ScamProb={res['scam_probability']*100:.2f}%, SafeProb={res['safe_probability']*100:.2f}%, Model={res['model']}")
    print("-" * 75)
