"""
KAVACH — Message ML Inference Service
Provides a clean service layer interface for message scam prediction.
"""
from typing import Any, Dict
from app.ai.message_detector import MessageScamDetector, predict_message_scam


def predict_message(text: str) -> Dict[str, Any]:
    """
    Analyzes message with the trained Logistic Regression model and TF-IDF vectorizer.
    Returns structured ML prediction data.
    """
    raw_res = predict_message_scam(text)
    
    return {
        "classification": raw_res["prediction"],
        "confidence": round(raw_res["confidence"] * 100, 2),
        "scam_probability": round(raw_res["scam_probability"] * 100, 2),
        "safe_probability": round(raw_res["safe_probability"] * 100, 2),
        "ml_prediction": raw_res["prediction"],
        "ml_confidence": round(raw_res["confidence"] * 100, 2),
        "model": raw_res["model"],
        "cleaned_text": raw_res.get("cleaned_text", "")
    }
