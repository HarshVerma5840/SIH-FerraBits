import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

def train_anomaly_model(dataset_path="backend/ml/data/packages_dataset.csv", models_dir="backend/ml/models"):
    os.makedirs(models_dir, exist_ok=True)
    
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}. Please run prepare_dataset.py first.")
        
    df = pd.read_csv(dataset_path)
    
    feature_cols = [
        "age_days", "release_frequency", "dependency_count", "dependency_growth",
        "maintainer_count", "maintainer_changes", "has_install_script", "obfuscation_score",
        "network_call_count", "vulnerability_history_count", "license_change_indicator", "reputation_score"
    ]
    
    X = df[feature_cols]
    
    # Load or fit scaler
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
        # Update/refit just in case
        X_scaled = scaler.fit_transform(X)
    else:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        joblib.dump(scaler, scaler_path)
        
    anomaly_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    anomaly_model.fit(X_scaled)
    
    anomaly_model_path = os.path.join(models_dir, "anomaly_detector.joblib")
    joblib.dump(anomaly_model, anomaly_model_path)
    print(f"Anomaly detector (Isolation Forest) saved to {anomaly_model_path}")

if __name__ == "__main__":
    train_anomaly_model()
