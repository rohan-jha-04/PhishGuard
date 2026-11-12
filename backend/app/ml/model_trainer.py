"""
Model Trainer & Evaluation Pipeline
Trains and compares Logistic Regression and Random Forest Classifiers.
Evaluates using Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix.
Prevents data leakage by fitting transformers strictly on training split.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

from app.ml.feature_extractor import (
    FEATURE_ORDER,
    extract_features_from_url,
    vectorize_features
)
from app.ml.dataset_builder import build_dataset_dataframe, DATASET_PROVENANCE

def train_and_evaluate_models(model_dir: str = None) -> dict:
    """
    Executes full academic ML training pipeline:
    1. Builds/loads dataset
    2. Feature extraction
    3. Stratified 80/20 train/test split
    4. Normalization via StandardScaler
    5. Training Logistic Regression & Random Forest
    6. Performance comparison & metric calculation
    7. Persistence of models and metrics
    """
    if model_dir is None:
        model_dir = os.path.join(os.path.dirname(__file__), "model_storage")
    os.makedirs(model_dir, exist_ok=True)

    # 1. Obtain dataset
    df = build_dataset_dataframe()
    urls = df["url"].tolist()
    y = np.array(df["label"].tolist())

    # 2. Extract features without leakage
    feature_matrix = []
    for u in urls:
        f_dict = extract_features_from_url(u)
        vec = vectorize_features(f_dict)
        feature_matrix.append(vec)
    X = np.array(feature_matrix)

    # 3. Stratified split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. Standard Scaler fit strictly on training set
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 5a. Train Logistic Regression
    lr_model = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    lr_model.fit(X_train_scaled, y_train)

    lr_pred = lr_model.predict(X_test_scaled)
    lr_proba = lr_model.predict_proba(X_test_scaled)[:, 1]

    lr_metrics = {
        "accuracy": round(float(accuracy_score(y_test, lr_pred)), 4),
        "precision": round(float(precision_score(y_test, lr_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, lr_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, lr_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, lr_proba)), 4),
        "confusion_matrix": confusion_matrix(y_test, lr_pred).tolist()
    }

    # 5b. Train Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced"
    )
    # Random Forest can train on unscaled or scaled; we fit on unscaled for natural tree interpretation
    rf_model.fit(X_train, y_train)

    rf_pred = rf_model.predict(X_test)
    rf_proba = rf_model.predict_proba(X_test)[:, 1]

    rf_metrics = {
        "accuracy": round(float(accuracy_score(y_test, rf_pred)), 4),
        "precision": round(float(precision_score(y_test, rf_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, rf_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, rf_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, rf_proba)), 4),
        "confusion_matrix": confusion_matrix(y_test, rf_pred).tolist()
    }

    # 6. Feature Importances from Random Forest (MDI Gini)
    importances = rf_model.feature_importances_
    feature_rankings = []
    for idx, f_name in enumerate(FEATURE_ORDER):
        feature_rankings.append({
            "feature": f_name,
            "importance": round(float(importances[idx]), 4),
            "percentage": round(float(importances[idx] * 100), 2)
        })
    feature_rankings.sort(key=lambda x: x["importance"], reverse=True)

    # 7. Package full results and provenance
    evaluation_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "name": DATASET_PROVENANCE["dataset_name"],
            "license": DATASET_PROVENANCE["license"],
            "citation": DATASET_PROVENANCE["citation"],
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "benign_count": int((y == 0).sum()),
            "phishing_count": int((y == 1).sum())
        },
        "selected_model": "Random Forest Classifier",
        "models": {
            "random_forest": {
                "name": "Random Forest Classifier",
                "hyperparameters": {
                    "n_estimators": 100,
                    "max_depth": 14,
                    "criterion": "gini",
                    "min_samples_split": 4
                },
                "metrics": rf_metrics
            },
            "logistic_regression": {
                "name": "Logistic Regression (L2 Regularized)",
                "hyperparameters": {
                    "max_iter": 1000,
                    "C": 1.0,
                    "penalty": "l2"
                },
                "metrics": lr_metrics
            }
        },
        "feature_importances": feature_rankings
    }

    # 8. Persist artifacts
    joblib.dump(rf_model, os.path.join(model_dir, "model.joblib"))
    joblib.dump(lr_model, os.path.join(model_dir, "lr_model.joblib"))
    joblib.dump(scaler, os.path.join(model_dir, "scaler.joblib"))

    metrics_file = os.path.join(model_dir, "metrics.json")
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(evaluation_report, f, indent=2)

    prov_file = os.path.join(model_dir, "dataset_provenance.json")
    with open(prov_file, "w", encoding="utf-8") as f:
        json.dump(DATASET_PROVENANCE, f, indent=2)

    return evaluation_report

if __name__ == "__main__":
    rep = train_and_evaluate_models()
    print("Academic ML Training Completed Successfully!")
    print(f"Random Forest Accuracy: {rep['models']['random_forest']['metrics']['accuracy']*100:.2f}%")
    print(f"Logistic Regression Accuracy: {rep['models']['logistic_regression']['metrics']['accuracy']*100:.2f}%")

