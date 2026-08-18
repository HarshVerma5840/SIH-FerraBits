import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

def train_malicious_model(dataset_path="backend/ml/data/packages_dataset.csv", models_dir="backend/ml/models"):
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
    y = df["is_suspicious"]
    
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
    else:
        scaler = StandardScaler()
        scaler.fit(X)
        joblib.dump(scaler, scaler_path)
        
    X_scaled = scaler.transform(X)
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_scaled, y)
    
    clf_path = os.path.join(models_dir, "malicious_classifier.joblib")
    joblib.dump(clf, clf_path)
    print(f"Malicious classifier (Random Forest) saved to {clf_path}")

if __name__ == "__main__":
    train_malicious_model()
