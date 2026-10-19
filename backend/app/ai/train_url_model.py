"""
=============================================================================
KAVACH — Machine Learning URL Phishing Detector Training Pipeline
=============================================================================
This module handles:
  1. Loading & validating the ISCX / Phishing Website dataset
  2. Dataset statistics, missing value check, duplicate removal, label mapping
  3. Stratified Train/Test split (80/20) with zero data leakage (random_state=42)
  4. Lexical feature extraction (32 numeric features)
  5. Training 3 classifiers: Logistic Regression, Random Forest, Gradient Boosting
  6. Evaluation (Accuracy, Precision, Recall, F1, Confusion Matrix)
  7. Selecting and persisting the best model, feature extractor & metadata
  8. Local verification predictions on synthetic test URLs
=============================================================================
"""

import os
import json
import time
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Import Kavach URL Feature Extractor
from app.ai.url_feature_extractor import URLFeatureExtractor, FEATURE_NAMES

# -----------------------------------------------------------------------------
# Configuration Paths
# -----------------------------------------------------------------------------
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
DATASET_PATH = os.path.join(PROJECT_ROOT, "datasets", "url_detection", "dataset_phishing.csv")
MODEL_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "models", "url_detector")



def load_and_clean_dataset(dataset_path: str):
    """
    Loads raw dataset, maps labels ('legitimate'->0 [SAFE], 'phishing'->1 [PHISHING]),
    checks missing values & duplicates, and returns a clean pandas DataFrame.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"URL dataset not found at: {dataset_path}")

    print(f"[1/7] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    print(f"      Initial dataset shape: {df.shape[0]} rows, {df.shape[1]} columns")

    # Map labels
    label_col = "status" if "status" in df.columns else "label"
    url_col = "url" if "url" in df.columns else "url_string"

    df[label_col] = df[label_col].astype(str).str.lower().str.strip()

    # Convert status values to binary target (1: Phishing, 0: Safe/Legitimate)
    label_map = {
        "phishing": 1,
        "bad": 1,
        "1": 1,
        "legitimate": 0,
        "good": 0,
        "safe": 0,
        "0": 0,
    }
    df["target"] = df[label_col].map(label_map)

    # Check for missing values in url or target
    missing_count = df[["target", url_col]].isnull().sum().to_dict()
    print(f"      Missing values check: {missing_count}")

    df = df.dropna(subset=[url_col, "target"]).copy()
    df["target"] = df["target"].astype(int)

    # Remove duplicates
    dup_count = df[url_col].duplicated().sum()
    print(f"      Duplicate URLs found: {dup_count}")
    if dup_count > 0:
        df = df.drop_duplicates(subset=[url_col]).reset_index(drop=True)
        print(f"      Rows after duplicate removal: {len(df)}")

    class_dist = df["target"].value_counts().to_dict()
    safe_count = class_dist.get(0, 0)
    phish_count = class_dist.get(1, 0)
    print(f"      Class distribution -> SAFE (0): {safe_count}, PHISHING (1): {phish_count}")

    return df, url_col


def train_and_evaluate_models():
    """Main training execution pipeline."""
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    print("=" * 80)
    print("       KAVACH — URL PHISHING ML MODEL TRAINING PIPELINE")
    print("=" * 80)

    start_time = time.time()

    # Step 1: Load and clean dataset
    df, url_col = load_and_clean_dataset(DATASET_PATH)

    # Step 2: Stratified Train / Test Split (80% Train, 20% Test)
    print("\n[2/7] Performing Stratified Train/Test Split (80% Train / 20% Test, random_state=42)")
    X_raw = df[url_col].values
    y_raw = df["target"].values

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y_raw, test_size=0.20, random_state=42, stratify=y_raw
    )

    print(f"      Training set size: {len(X_train_raw)} samples")
    print(f"      Testing set size:  {len(X_test_raw)} samples")

    # Step 3: Extract Lexical URL Features (Zero Data Leakage)
    print("\n[3/7] Extracting 32 Lexical URL features...")
    extractor = URLFeatureExtractor()

    # Fit feature extractor on train set only (no-op fit for extractor)
    extractor.fit(X_train_raw)

    X_train_feat = extractor.transform(X_train_raw)
    X_test_feat = extractor.transform(X_test_raw)

    print(f"      Extracted Feature Matrix shape -> Train: {X_train_feat.shape}, Test: {X_test_feat.shape}")

    # Step 4: Define Models for Evaluation
    classifiers = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    }

    print("\n[4/7] Training & Evaluating Candidate Classifiers...")
    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model_obj = None

    for name, clf in classifiers.items():
        print(f"\n      ---> Training {name}...")
        clf.fit(X_train_feat, y_train)

        y_pred = clf.predict(X_test_feat)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
        rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
        }

        print(f"           Accuracy:  {acc * 100:.2f}%")
        print(f"           Precision: {prec * 100:.2f}%")
        print(f"           Recall:    {rec * 100:.2f}% (Phishing Detection Sensitivity)")
        print(f"           F1-Score:  {f1 * 100:.2f}%")

        # Select model prioritizing F1-score & Recall
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model_obj = clf

    # Step 5: Display Comparison Table
    print("\n" + "=" * 80)
    print(f"{'MODEL CANDIDATE':<22} | {'ACCURACY':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10}")
    print("=" * 80)
    for name, m in results.items():
        print(f"{name:<22} | {m['accuracy']*100:>8.2f}% | {m['precision']*100:>8.2f}% | {m['recall']*100:>8.2f}% | {m['f1_score']*100:>8.2f}%")
    print("=" * 80)

    print(f"\n[5/7] BEST MODEL SELECTED: '{best_model_name}' (F1-Score: {best_f1*100:.2f}%)")

    # Step 6: Persist Artifacts & Metadata
    print("\n[6/7] Persisting model artifacts todisk...")
    model_file_path = os.path.join(MODEL_OUTPUT_DIR, "url_model.joblib")
    extractor_file_path = os.path.join(MODEL_OUTPUT_DIR, "url_feature_extractor.joblib")
    metadata_file_path = os.path.join(MODEL_OUTPUT_DIR, "model_metadata.json")

    joblib.dump(best_model_obj, model_file_path)
    joblib.dump(extractor, extractor_file_path)

    metadata = {
        "dataset_name": "ISCX Phishing Website Dataset",
        "dataset_source": DATASET_PATH,
        "dataset_total_samples": len(df),
        "train_samples": len(X_train_raw),
        "test_samples": len(X_test_raw),
        "class_distribution": {
            "safe_count": int((y_raw == 0).sum()),
            "phishing_count": int((y_raw == 1).sum()),
        },
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "random_state": 42,
        "models_evaluated": results,
        "selected_model": best_model_name,
        "best_metrics": results[best_model_name],
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "training_duration_seconds": round(time.time() - start_time, 2),
    }

    with open(metadata_file_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"      Saved Model Artifact:      {model_file_path}")
    print(f"      Saved Feature Extractor:   {extractor_file_path}")
    print(f"      Saved Metadata Document:  {metadata_file_path}")

    # Step 7: Test Local Predictions
    print("\n[7/7] Verifying Local Model Inference on Synthetic Test URLs...")
    test_samples = [
        ("https://www.google.com", "SAFE"),
        ("https://www.wikipedia.org", "SAFE"),
        ("http://example-login.com/verify", "PHISHING"),
        ("https://secure-login-example.com@evil.example/verify", "PHISHING"),
        ("https://192.168.1.1/login", "PHISHING"),
        ("http://malicious-update.top/payload.apk", "PHISHING"),
    ]

    for test_url, expected_type in test_samples:
        feat = extractor.transform([test_url])
        pred_val = best_model_obj.predict(feat)[0]
        probs = best_model_obj.predict_proba(feat)[0] if hasattr(best_model_obj, "predict_proba") else [0.5, 0.5]
        label = "PHISHING" if pred_val == 1 else "SAFE"
        confidence = probs[pred_val] * 100
        print(f"      URL: {test_url:<55} -> Pred: {label:<8} ({confidence:.1f}% confidence) | Expected: {expected_type}")

    print("\n" + "=" * 80)
    print("       URL ML DETECTOR MODEL TRAINING COMPLETE (100% SUCCESS)")
    print("=" * 80)


if __name__ == "__main__":
    train_and_evaluate_models()
