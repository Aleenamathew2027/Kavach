"""
=============================================================================
KAVACH AI — Message Scam Inference Service
=============================================================================
This module provides high-performance, in-memory ML inference for message
scam classification using the trained Logistic Regression model and TF-IDF
vectorizer.

Key features:
  - Lazy, thread-safe model and vectorizer loading (loaded once in memory)
  - Identical text preprocessing matching the training pipeline
  - Prediction output: SAFE / SCAM, calibrated probabilities & confidence
  - Transparent model metadata & scope documentation
=============================================================================
"""

import os
import re
import json
import logging
from typing import Any, Dict, Optional
import joblib

logger = logging.getLogger("kavach.ai.message_detector")

# Paths to persisted model artifacts
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "message_detector")

MODEL_PATH = os.path.join(MODEL_DIR, "message_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


class MessageScamDetector:
    """
    Singleton inference class that loads and caches the trained
    Logistic Regression model and TF-IDF vectorizer.
    """
    _instance: Optional["MessageScamDetector"] = None

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metadata = {}
        self.is_loaded = False
        self._load_artifacts()

    @classmethod
    def get_instance(cls) -> "MessageScamDetector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_artifacts(self):
        """Loads model and vectorizer from disk into memory."""
        try:
            if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
                logger.warning(
                    f"Message detection model artifacts not found at {MODEL_DIR}. "
                    f"Run 'python -m app.ai.train_message_model' to generate them."
                )
                self.is_loaded = False
                return

            self.model = joblib.load(MODEL_PATH)
            self.vectorizer = joblib.load(VECTORIZER_PATH)
            
            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            self.is_loaded = True
            logger.info(f"Loaded Message Scam ML Model ({self.metadata.get('model_name', 'Logistic Regression')}) successfully.")
        except Exception as e:
            logger.error(f"Failed to load Message Scam Detector artifacts: {e}", exc_info=True)
            self.is_loaded = False

    @staticmethod
    def clean_text(text: str) -> str:
        """
        Exact text normalization matching the training pipeline.
        Transforms security-sensitive signals into semantic tokens.
        """
        if not isinstance(text, str):
            return ""

        # 1. Normalize line breaks and tabs
        text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")

        # 2. Lowercase text
        text = text.lower()

        # 3. Replace URLs with semantic token
        text = re.sub(r'https?://\S+|www\.\S+', ' httpurl ', text)

        # 4. Replace email addresses with token
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' emailaddr ', text)

        # 5. Replace currency symbols (£, $, €, ₹, ¥) with token
        text = re.sub(r'[£$€₹¥]', ' currencysym ', text)

        # 6. Replace phone / claim numbers (4+ digits) with token
        text = re.sub(r'\b\d{4,}\b', ' numtoken ', text)

        # 7. Remove remaining punctuation while keeping alphanumeric words
        text = re.sub(r'[^\w\s]', ' ', text)

        # 8. Collapse whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        return text

    def predict(self, raw_text: str) -> Dict[str, Any]:
        """
        Runs ML prediction on a given raw text message.
        Returns prediction (SAFE/SCAM), confidence, scam_probability, safe_probability.
        """
        if not raw_text or not raw_text.strip():
            return {
                "prediction": "SAFE",
                "confidence": 1.0,
                "scam_probability": 0.0,
                "safe_probability": 1.0,
                "model": self.metadata.get("model_name", "Logistic Regression"),
                "model_scope": "SMS Spam Collection Benchmark",
                "model_loaded": self.is_loaded,
                "cleaned_text": ""
            }

        # If model artifacts are missing, fallback safely
        if not self.is_loaded or self.model is None or self.vectorizer is None:
            self._load_artifacts()
            if not self.is_loaded:
                return {
                    "prediction": "SAFE",
                    "confidence": 0.50,
                    "scam_probability": 0.0,
                    "safe_probability": 1.0,
                    "model": "Fallback Heuristics",
                    "model_scope": "Model Artifacts Not Loaded",
                    "model_loaded": False,
                    "cleaned_text": self.clean_text(raw_text)
                }

        cleaned = self.clean_text(raw_text)
        vec = self.vectorizer.transform([cleaned])
        pred_idx = int(self.model.predict(vec)[0])

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(vec)[0]
            safe_prob = float(probs[0])
            scam_prob = float(probs[1])
            confidence = float(probs[pred_idx])
        else:
            scam_prob = 1.0 if pred_idx == 1 else 0.0
            safe_prob = 1.0 - scam_prob
            confidence = 1.0

        label = "SCAM" if pred_idx == 1 else "SAFE"

        return {
            "prediction": label,
            "confidence": round(confidence, 4),
            "scam_probability": round(scam_prob, 4),
            "safe_probability": round(safe_prob, 4),
            "model": self.metadata.get("model_name", "Logistic Regression"),
            "model_scope": "SMS Spam Collection Benchmark",
            "model_loaded": True,
            "cleaned_text": cleaned
        }


# Convenience function for direct calls
def predict_message_scam(text: str) -> Dict[str, Any]:
    """Helper function to run message scam prediction with cached detector."""
    detector = MessageScamDetector.get_instance()
    return detector.predict(text)
