"""
XGBoost Phishing Model Trainer for PhishGuard Engine
Loads UCI Phishing Dataset, trains XGBClassifier (80/20 train/test split),
evaluates accuracy (>95%), and saves pickle model to backend/app/models/xgboost_phishing.pkl.
"""

import os
import pickle
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from xgboost import XGBClassifier, plot_importance

ML_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(ML_DIR, "phishing_dataset.csv")

MODELS_DIR = os.path.abspath(os.path.join(ML_DIR, "..", "models"))
MODEL_PKL_PATH = os.path.join(MODELS_DIR, "xgboost_phishing.pkl")
PLOT_PATH = os.path.join(MODELS_DIR, "feature_importance.png")


def train_model():
    """Train XGBoost model on UCI phishing dataset."""
    if not os.path.exists(CSV_PATH):
        from backend.app.ml.download_dataset import download_dataset
        download_dataset()

    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR, exist_ok=True)

    print(f"[ML Trainer] Loading dataset from {CSV_PATH}...")
    df = pd.read_csv(CSV_PATH)
    print(f"[ML Trainer] Dataset shape: {df.shape}")

    # Drop Index/id column if exists
    if "Index" in df.columns:
        df = df.drop(columns=["Index"])
    if "id" in df.columns:
        df = df.drop(columns=["id"])

    target_col = "Result" if "Result" in df.columns else df.columns[-1]

    # Target variable mapping: Phishing = 1 (Result == -1), Legitimate = 0 (Result == 1)
    X = df.drop(columns=[str(target_col)])
    y = df[target_col].apply(lambda v: 1 if v == -1 else 0)

    print(f"[ML Trainer] Feature columns count: {X.shape[1]}")
    print(f"[ML Trainer] Target distribution: Phishing(1)={sum(y==1)}, Legitimate(0)={sum(y==0)}")

    # 80/20 Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

    # Initialize XGBoost Classifier
    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        use_label_encoder=False
    )

    print("[ML Trainer] Fitting XGBoost Classifier...")
    model.fit(X_train, y_train)

    # Predictions & Evaluation
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    acc_percent = accuracy * 100.0

    print("\n==========================================")
    print(f"  XGBoost Phishing Model Accuracy: {acc_percent:.2f}%")
    print("==========================================\n")

    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save trained model to pickle
    model_meta = {
        "model": model,
        "feature_names": list(X.columns),
        "accuracy": accuracy,
    }

    with open(MODEL_PKL_PATH, "wb") as f:
        pickle.dump(model_meta, f)

    file_size_mb = os.path.getsize(MODEL_PKL_PATH) / (1024 * 1024)
    print(f"\n[ML Trainer] Model saved to {MODEL_PKL_PATH} ({file_size_mb:.2f} MB)")

    # Plot & Save Feature Importance Chart
    try:
        fig, ax = plt.subplots(figsize=(10, 8))
        plot_importance(model, max_num_features=15, ax=ax, title="PhishGuard XGBoost Feature Importance")
        plt.tight_layout()
        plt.savefig(PLOT_PATH, dpi=150)
        plt.close()
        print(f"[ML Trainer] Feature importance plot saved to {PLOT_PATH}")
    except Exception as img_err:
        print(f"[ML Trainer Plot Error]: {img_err}")

    return model_meta


if __name__ == "__main__":
    train_model()
