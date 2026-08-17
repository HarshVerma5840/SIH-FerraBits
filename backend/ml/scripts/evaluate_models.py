import os
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

def evaluate_models(dataset_path="backend/ml/data/packages_dataset.csv", models_dir="backend/ml/models"):
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}. Please run prepare_dataset.py first.")
        
    df = pd.read_csv(dataset_path)
    
    feature_cols = [
        "age_days", "release_frequency", "dependency_count", "dependency_growth",
        "maintainer_count", "maintainer_changes", "has_install_script", "obfuscation_score",
        "network_call_count", "vulnerability_history_count", "license_change_indicator", "reputation_score"
    ]
    
    X = df[feature_cols]
    y = df["is_suspicious"]
    
    # Load scaler and scale
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    anomaly_model_path = os.path.join(models_dir, "anomaly_detector.joblib")
    clf_path = os.path.join(models_dir, "malicious_classifier.joblib")
    
    if not all(os.path.exists(p) for p in [scaler_path, anomaly_model_path, clf_path]):
        raise FileNotFoundError("Models or scaler not found. Please train them first.")
        
    scaler = joblib.load(scaler_path)
    anomaly_model = joblib.load(anomaly_model_path)
    clf = joblib.load(clf_path)
    
    X_scaled = scaler.transform(X)
    
    print("====================================================")
    print("MODEL EVALUATION")
    print("====================================================")
    
    # 1. Anomaly Detection (Isolation Forest)
    # Isolation Forest predicts -1 for anomalies and 1 for normal data
    anomaly_preds = anomaly_model.predict(X_scaled)
    # Convert to 1 for anomalies (is_suspicious) and 0 for normal
    anomaly_binary_preds = np.where(anomaly_preds == -1, 1, 0)
    
    print("\n[AI ENGINE #1] Anomaly Detection (Isolation Forest):")
    print(f"Detected Anomalies: {sum(anomaly_binary_preds)} / {len(anomaly_binary_preds)} ({(sum(anomaly_binary_preds)/len(anomaly_binary_preds))*100:.2f}%)")
    print("Classification Report against ground truth labels:")
    print(classification_report(y, anomaly_binary_preds))
    
    # 2. Malicious Classification (Random Forest)
    clf_preds = clf.predict(X_scaled)
    print("\n[AI ENGINE #2] Malicious Dependency Classification (Random Forest):")
    print(f"Classification Accuracy: {accuracy_score(y, clf_preds):.4f}")
    print("Classification Report:")
    print(classification_report(y, clf_preds))
    print("Confusion Matrix:")
    print(confusion_matrix(y, clf_preds))
    
    print("\nFeature Importances for Malicious Classifier:")
    importances = clf.feature_importances_
    for name, importance in sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True):
        print(f"  - {name}: {importance:.4f}")

if __name__ == "__main__":
    evaluate_models()
