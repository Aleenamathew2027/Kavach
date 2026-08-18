"""
=============================================================================
KAVACH — Machine Learning Message Scam Detection Training Pipeline
=============================================================================
This module handles:
  1. Loading & validating the SMS Spam Collection dataset
  2. Preprocessing & text normalization
  3. Stratified Train/Test split (80/20) with zero data leakage
  4. TF-IDF feature extraction (unigrams + bigrams)
  5. Training 3 classifiers: Logistic Regression, Naive Bayes, Linear SVM
  6. Comprehensive evaluation (Accuracy, Precision, Recall, F1, Confusion Matrix)
  7. Selecting and persisting the best model & vectorizer
  8. Local inference testing on unseen realistic messages
=============================================================================
"""

import os
import re
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# -----------------------------------------------------------------------------
# Configuration Paths
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATASET_PATH = os.path.join(PROJECT_ROOT, "datasets", "message_detection", "SMSSpamCollection")
MODEL_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "models", "message_detector")


def clean_text(text: str) -> str:
    """
    Cleans raw message text for NLP feature extraction.
    Retains security-critical signals (URLs, currency symbols, phone numbers)
    by normalizing them into semantic tokens.
    """
    if not isinstance(text, str):
        return ""
    
    # 1. Normalize line breaks and tabs
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    
    # 2. Lowercase text
    text = text.lower()
    
    # 3. Replace URLs with a semantic token
    text = re.sub(r'https?://\S+|www\.\S+', ' httpurl ', text)
    
    # 4. Replace email addresses with a token
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' emailaddr ', text)
    
    # 5. Replace currency symbols with a token
    text = re.sub(r'[£$€₹¥]', ' currencysym ', text)
    
    # 6. Replace multi-digit phone/claim numbers (4 or more digits) with a token
    text = re.sub(r'\b\d{4,}\b', ' numtoken ', text)
    
    # 7. Remove special punctuation characters but keep standard word letters and whitespace
    text = re.sub(r'[^\w\s]', ' ', text)
    
    # 8. Collapse consecutive whitespaces
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def load_and_preprocess_dataset(dataset_path: str):
    """
    Loads raw dataset, maps labels (ham->SAFE, spam->SCAM),
    cleans messages, and returns a sanitized DataFrame.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")
    
    print(f"[1/7] Loading dataset from: {dataset_path}")
    df = pd.read_csv(
        dataset_path,
        sep='\t',
        names=['raw_label', 'raw_message'],
        encoding='utf-8',
        on_bad_lines='skip'
    )
    
    # Map labels: ham -> 0 (SAFE), spam -> 1 (SCAM)
    df['label_name'] = df['raw_label'].map({'ham': 'SAFE', 'spam': 'SCAM'})
    df['label'] = df['raw_label'].map({'ham': 0, 'spam': 1})
    
    # Clean text
    print("[2/7] Preprocessing & normalizing text samples...")
    df['cleaned_message'] = df['raw_message'].apply(clean_text)
    
    # Drop any potential empty rows after cleaning
    df = df[df['cleaned_message'].str.len() > 0].reset_index(drop=True)
    
    total_count = len(df)
    ham_count = (df['label'] == 0).sum()
    spam_count = (df['label'] == 1).sum()
    
    print(f"      Total Valid Samples : {total_count}")
    print(f"      SAFE (Ham) Samples  : {ham_count} ({ham_count / total_count * 100:.2f}%)")
    print(f"      SCAM (Spam) Samples : {spam_count} ({spam_count / total_count * 100:.2f}%)")
    
    return df


def split_data(df: pd.DataFrame, test_size: float = 0.20, random_state: int = 42):
    """
    Performs a stratified train/test split to maintain class balance in both subsets.
    """
    print(f"[3/7] Splitting data ({int((1-test_size)*100)}% Train / {int(test_size*100)}% Test, random_state={random_state})...")
    X = df['cleaned_message'].values
    y = df['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        stratify=y,
        random_state=random_state
    )
    
    print(f"      Training set size   : {len(X_train)} messages")
    print(f"      Testing set size    : {len(X_test)} messages")
    
    return X_train, X_test, y_train, y_test


def build_vectorizer(X_train: np.ndarray):
    """
    Fits TF-IDF vectorizer ONLY on training set to prevent data leakage.
    Uses unigram + bigram features (ngram_range=(1,2)).
    """
    print("[4/7] Fitting TF-IDF Vectorizer on training data...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        min_df=2,
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    print(f"      Vocabulary size     : {len(vectorizer.vocabulary_)} features")
    return vectorizer, X_train_vec


def train_and_evaluate_models(X_train_vec, X_test_vec, y_train, y_test):
    """
    Trains and benchmarks:
      1. Logistic Regression
      2. Multinomial Naive Bayes
      3. Linear SVM (Calibrated for probability estimation)
    """
    print("[5/7] Training and evaluating 3 candidate classifiers...\n")
    
    models = {
        "Logistic Regression": LogisticRegression(
            C=2.0,
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        ),
        "Multinomial Naive Bayes": MultinomialNB(
            alpha=0.1
        ),
        "Linear SVM (Calibrated)": CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, class_weight='balanced', random_state=42),
            cv=5
        )
    }
    
    results = {}
    
    for name, model in models.items():
        # Train
        model.fit(X_train_vec, y_train)
        
        # Predict on Test set
        y_pred = model.predict(X_test_vec)
        
        # Calculate metrics for SCAM class (pos_label=1)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, pos_label=1, zero_division=0)
        rec = recall_score(y_test, y_pred, pos_label=1, zero_division=0)
        f1 = f1_score(y_test, y_pred, pos_label=1, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        
        # Unpack confusion matrix: tn, fp, fn, tp
        tn, fp, fn, tp = cm.ravel()
        
        results[name] = {
            "model": model,
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "confusion_matrix": cm.tolist()
        }
    
    return results


def print_comparison_table(results: dict):
    """
    Prints a formatted markdown-style comparison table.
    """
    print("=" * 80)
    print("                       MODEL COMPARISON BENCHMARK TABLE                        ")
    print("=" * 80)
    header = f"{'Model':<26} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'TN':<5} {'FP':<5} {'FN':<5} {'TP':<5}"
    print(header)
    print("-" * 80)
    for name, m in results.items():
        row = (
            f"{name:<26} | "
            f"{m['accuracy']*100:>8.2f}% | "
            f"{m['precision']*100:>8.2f}% | "
            f"{m['recall']*100:>8.2f}% | "
            f"{m['f1']*100:>8.2f}% | "
            f"{m['tn']:<5} {m['fp']:<5} {m['fn']:<5} {m['tp']:<5}"
        )
        print(row)
    print("=" * 80)
    print("TN: True Safe, FP: False Alarm (Safe flagged as Scam)")
    print("FN: Missed Scam (Dangerous), TP: Correctly Caught Scam\n")


def select_best_model(results: dict):
    """
    Selects the best model prioritizing F1-score on the SCAM class
    and minimal False Negatives (high Recall).
    """
    # Primary sorting key: SCAM F1-score, secondary: Recall
    best_name = max(results.keys(), key=lambda k: (results[k]['f1'], results[k]['recall']))
    best_info = results[best_name]
    return best_name, best_info


def save_artifacts(best_name: str, best_model, vectorizer: TfidfVectorizer, all_results: dict):
    """
    Persists the trained model, vectorizer, and metadata to disk.
    """
    print(f"[6/7] Saving best model ({best_name}) and vectorizer to: {MODEL_OUTPUT_DIR}")
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    
    model_path = os.path.join(MODEL_OUTPUT_DIR, "message_model.joblib")
    vectorizer_path = os.path.join(MODEL_OUTPUT_DIR, "tfidf_vectorizer.joblib")
    metadata_path = os.path.join(MODEL_OUTPUT_DIR, "model_metadata.json")
    
    # Save joblib binary artifacts
    joblib.dump(best_model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    
    # Prepare serializable metadata
    metadata = {
        "model_name": best_name,
        "framework": "scikit-learn",
        "vectorizer": "TfidfVectorizer",
        "vocabulary_size": len(vectorizer.vocabulary_),
        "ngram_range": [1, 2],
        "classes": ["SAFE", "SCAM"],
        "benchmark_metrics": {
            k: {
                "accuracy": v["accuracy"],
                "precision": v["precision"],
                "recall": v["recall"],
                "f1": v["f1"],
                "confusion_matrix": v["confusion_matrix"]
            }
            for k, v in all_results.items()
        }
    }
    
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        
    print(f"      Saved Model File      : {model_path}")
    print(f"      Saved Vectorizer File : {vectorizer_path}")
    print(f"      Saved Metadata JSON   : {metadata_path}\n")
    
    return model_path, vectorizer_path, metadata_path


def predict_message(raw_text: str, model, vectorizer) -> dict:
    """
    Predicts whether a single message is SAFE or SCAM.
    Returns label, probability/confidence, and cleaned text.
    """
    cleaned = clean_text(raw_text)
    vec = vectorizer.transform([cleaned])
    pred_idx = model.predict(vec)[0]
    
    confidence = None
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(vec)[0]
        confidence = float(probs[pred_idx])
        scam_prob = float(probs[1])
    else:
        scam_prob = float(pred_idx)
        confidence = 1.0
        
    label = "SCAM" if pred_idx == 1 else "SAFE"
    
    return {
        "label": label,
        "confidence": confidence,
        "scam_probability": scam_prob,
        "cleaned_input": cleaned
    }


def run_inference_tests(model, vectorizer, model_name: str):
    """
    Tests the trained model on 5 diverse real-world scenario messages.
    """
    print("[7/7] Running Inference Validation on Example Messages...")
    test_cases = [
        {
            "category": "Normal Legitimate Message",
            "text": "Hey Mom, I will be reaching home by 7:30 PM. Please keep dinner ready!"
        },
        {
            "category": "Typical Promotional Spam",
            "text": "Exclusive weekend offer! Get 50% discount on all sunglasses. Visit our store or click http://promo-deals.com to shop now."
        },
        {
            "category": "Phishing / Security Alert",
            "text": "Your SBI bank account has been locked due to suspicious activity. Update your KYC immediately at http://sbi-kyc-update.com/verify to prevent permanent suspension."
        },
        {
            "category": "Fake Lottery Prize",
            "text": "CONGRATULATIONS!! You have won £1,000,000 cash prize in the International Mobile Lottery. Call 08712345678 to claim your prize reward KL782 today."
        },
        {
            "category": "Urgent Link Action",
            "text": "URGENT NOTICE: Your electricity bill is pending Rs 4,520. Power supply will be disconnected tonight. Pay immediately at http://power-bill-pay.in"
        }
    ]
    
    print("-" * 80)
    for i, item in enumerate(test_cases, 1):
        res = predict_message(item["text"], model, vectorizer)
        print(f"Test #{i} | {item['category']}")
        print(f"  Input Text : \"{item['text']}\"")
        print(f"  Prediction : [{res['label']}] (Confidence: {res['confidence']*100:.2f}%, Scam Prob: {res['scam_probability']*100:.2f}%)")
        print("-" * 80)


def main():
    print("\n" + "=" * 80)
    print("        KAVACH AI — MESSAGE SCAM DETECTION MODEL TRAINING PIPELINE        ")
    print("=" * 80 + "\n")
    
    # 1. Load & Preprocess
    df = load_and_preprocess_dataset(DATASET_PATH)
    
    # 2. Train / Test Split
    X_train, X_test, y_train, y_test = split_data(df, test_size=0.20, random_state=42)
    
    # 3. Vectorize (Fit on Train ONLY)
    vectorizer, X_train_vec = build_vectorizer(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # 4. Train & Evaluate 3 Models
    results = train_and_evaluate_models(X_train_vec, X_test_vec, y_train, y_test)
    
    # 5. Print Comparison Table
    print_comparison_table(results)
    
    # 6. Select Best Model
    best_name, best_info = select_best_model(results)
    print(f"--> Selected Best Model: {best_name}")
    print(f"    Reason: Highest F1-score ({best_info['f1']*100:.2f}%) on SCAM class with minimal False Negatives (FN={best_info['fn']}).\n")
    
    # 7. Save Model & Vectorizer
    model_path, vec_path, meta_path = save_artifacts(best_name, best_info["model"], vectorizer, results)
    
    # 8. Test Inference
    run_inference_tests(best_info["model"], vectorizer, best_name)
    
    print("\n" + "=" * 80)
    print(" [SUCCESS] TRAINING PIPELINE COMPLETED SUCCESSFULLY & ARTIFACTS PERSISTED")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
