import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

def train_models(dataset_path="backend/ml/data/packages_dataset.csv", models_dir="backend/ml/models"):
    os.makedirs(models_dir, exist_ok=True)
    
    # Load dataset
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}. Please run prepare_dataset.py first.")
        
    df = pd.read_csv(dataset_path)
    
    # Define features
    feature_cols = [
        "age_days", "release_frequency", "dependency_count", "dependency_growth",
        "maintainer_count", "maintainer_changes", "has_install_script", "obfuscation_score",
        "network_call_count", "vulnerability_history_count", "license_change_indicator", "reputation_score"
    ]
    
    X = df[feature_cols]
    y = df["is_suspicious"]
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Save scaler
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    joblib.dump(scaler, scaler_path)
    print(f"Scaler saved to {scaler_path}")
    
    # 1. Train Anomaly Detection (Isolation Forest)
    # Isolation Forest is unsupervised. We train it on all data.
    # contamination = percentage of expected anomalies (around 10%)
    anomaly_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    anomaly_model.fit(X_scaled)
    
    anomaly_model_path = os.path.join(models_dir, "anomaly_detector.joblib")
    joblib.dump(anomaly_model, anomaly_model_path)
    print(f"Anomaly detector (Isolation Forest) saved to {anomaly_model_path}")
    
    # 2. Train Malicious Classifier (Random Forest)
    # Split into train/test
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate on test set
    accuracy = clf.score(X_test, y_test)
    print(f"Malicious Classifier Test Accuracy: {accuracy:.4f}")
    
    clf_path = os.path.join(models_dir, "malicious_classifier.joblib")
    joblib.dump(clf, clf_path)
    print(f"Malicious classifier (Random Forest) saved to {clf_path}")

if __name__ == "__main__":
    train_models()
