"""
Model Management.
Responsibility: Handle the loading of serialized ML models and provide a consistent interface
for inference, masking any underlying IO or library exceptions.
"""
import os
import joblib

# Model paths
MODELS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "ml", "models"
)
ANOMALY_MODEL_PATH = os.path.join(MODELS_DIR, "anomaly_detector.joblib")
MALICIOUS_MODEL_PATH = os.path.join(MODELS_DIR, "malicious_classifier.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")

MODEL_VERSION = "1.0.0"

class ModelLoader:
    def __init__(self):
        self.anomaly_model = None
        self.malicious_model = None
        self.scaler = None
        self.is_loaded = False
        self.load_models()

    def load_models(self):
        try:
            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
            if os.path.exists(ANOMALY_MODEL_PATH):
                self.anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
            if os.path.exists(MALICIOUS_MODEL_PATH):
                self.malicious_model = joblib.load(MALICIOUS_MODEL_PATH)
            
            if self.anomaly_model or self.malicious_model:
                print(f"[ai_engine.model] ML models loaded successfully (version {MODEL_VERSION})")
                self.is_loaded = True
            else:
                print("[ai_engine.model] No serialized models found. Engine will use fallback heuristics.")
        except Exception as e:
            print(f"[ai_engine.model] Warning: Failed to load ML models: {e}. Falling back to heuristics.")

    def get_anomaly_model(self):
        return self.anomaly_model
        
    def get_malicious_model(self):
        return self.malicious_model
        
    def get_scaler(self):
        return self.scaler

# Singleton instance
model_manager = ModelLoader()
