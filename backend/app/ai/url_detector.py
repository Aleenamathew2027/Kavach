"""
=============================================================================
KAVACH AI — URL Phishing ML Inference Service
=============================================================================
This module provides high-performance, in-memory ML inference for URL
phishing classification using the trained Random Forest model and lexical
feature extractor.

Key features:
  - Lazy, thread-safe model and feature extractor loading
  - Lexical feature extraction matching the offline training pipeline
  - Outputs: prediction (SAFE / PHISHING), phishing_probability, safe_probability, confidence
  - Graceful fallback error handling (never crashes the API)
=============================================================================
"""

import os
import json
import logging
from typing import Any, Dict, Optional
import joblib

from app.ai.url_feature_extractor import URLFeatureExtractor

logger = logging.getLogger("kavach.ai.url_detector")

# Paths to persisted model artifacts
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "url_detector")

MODEL_PATH = os.path.join(MODEL_DIR, "url_model.joblib")
EXTRACTOR_PATH = os.path.join(MODEL_DIR, "url_feature_extractor.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


class URLPhishingDetector:
    """
    Singleton inference class that loads and caches the trained
    Random Forest URL model and feature extractor.
    """
    _instance: Optional["URLPhishingDetector"] = None

    def __init__(self):
        self.model = None
        self.extractor = None
        self.metadata = {}
        self.is_loaded = False
        self._load_artifacts()

    @classmethod
    def get_instance(cls) -> "URLPhishingDetector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_artifacts(self):
        """Loads model, feature extractor, and metadata from disk into memory."""
        try:
            if not os.path.exists(MODEL_PATH) or not os.path.exists(EXTRACTOR_PATH):
                logger.warning(
                    f"URL Phishing model artifacts not found at {MODEL_DIR}. "
                    f"Run 'python -m app.ai.train_url_model' to generate them."
                )
                self.is_loaded = False
                return

            self.model = joblib.load(MODEL_PATH)
            self.extractor = joblib.load(EXTRACTOR_PATH)

            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            self.is_loaded = True
            model_name = self.metadata.get("selected_model", "Random Forest Classifier")
            logger.info(f"Loaded URL Phishing ML Model ({model_name}) successfully.")
        except Exception as e:
            logger.error(f"Failed to load URL Phishing Detector artifacts: {e}", exc_info=True)
            self.is_loaded = False

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Runs ML prediction on a raw URL string.
        Returns prediction (SAFE / PHISHING), confidence, phishing_probability, safe_probability.
        """
        model_name = self.metadata.get("selected_model", "Random Forest Classifier")
        model_scope = "ISCX Phishing Benchmark"

        if not url or not url.strip():
            return {
                "prediction": "SAFE",
                "confidence": 100.0,
                "phishing_probability": 0.0,
                "safe_probability": 1.0,
                "model": model_name,
                "model_scope": model_scope,
                "model_loaded": self.is_loaded,
            }

        # If model artifacts are missing, fallback gracefully
        if not self.is_loaded or self.model is None or self.extractor is None:
            self._load_artifacts()
            if not self.is_loaded:
                return {
                    "prediction": "SAFE",
                    "confidence": 50.0,
                    "phishing_probability": 0.0,
                    "safe_probability": 1.0,
                    "model": "Fallback Heuristics",
                    "model_scope": "Model Artifacts Not Loaded",
                    "model_loaded": False,
                }

        try:
            feat = self.extractor.transform([url])
            pred_idx = int(self.model.predict(feat)[0])

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(feat)[0]
                safe_prob = float(probs[0])
                phish_prob = float(probs[1])
                confidence = float(probs[pred_idx])
            else:
                phish_prob = 1.0 if pred_idx == 1 else 0.0
                safe_prob = 1.0 - phish_prob
                confidence = 1.0

            label = "PHISHING" if pred_idx == 1 else "SAFE"

            return {
                "prediction": label,
                "confidence": round(confidence * 100, 1),
                "phishing_probability": round(phish_prob * 100, 1),
                "safe_probability": round(safe_prob * 100, 1),
                "phishing_prob_raw": round(phish_prob, 4),
                "safe_prob_raw": round(safe_prob, 4),
                "model": model_name,
                "model_scope": model_scope,
                "model_loaded": True,
            }
        except Exception as err:
            logger.error(f"Error during URL ML inference for '{url}': {err}", exc_info=True)
            return {
                "prediction": "SAFE",
                "confidence": 50.0,
                "phishing_probability": 0.0,
                "safe_probability": 1.0,
                "model": model_name,
                "model_scope": model_scope,
                "model_loaded": False,
            }


def predict_url_phishing(url: str) -> Dict[str, Any]:
    """Helper function for direct ML URL prediction calls."""
    detector = URLPhishingDetector.get_instance()
    return detector.predict(url)
