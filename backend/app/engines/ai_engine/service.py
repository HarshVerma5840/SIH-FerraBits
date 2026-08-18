"""
AI Engine Facade Service.
Responsibility: Provide the single entry point for deterministic engines to query ML logic.
"""
from backend.app.engines.ai_engine.feature_builder import build_features_vector, FEATURE_SCHEMA_VERSION
from backend.app.engines.ai_engine.model import model_manager, MODEL_VERSION
from backend.app.engines.ai_engine.anomaly_detector import (
    compute_anomaly, generate_anomaly_signals,
    compute_suspicion, generate_suspicion_signals
)
from backend.app.engines.ai_engine.prediction import AnomalyPredictionResult, SuspiciousDependencyResult

def run_anomaly_detection(component: dict) -> dict:
    """
    Analyzes a component and returns an AnomalyPredictionResult dict.
    This maintains backward compatibility with the legacy `ml_engine.run_anomaly_detection` dict return type.
    """
    purl = component.get("purl", "UNKNOWN")
    features = build_features_vector(component)
    
    score, prob, classification = compute_anomaly(
        features, 
        model_manager.get_scaler(), 
        model_manager.get_anomaly_model()
    )
    
    signals = generate_anomaly_signals(features)
    
    # Enforce schema validation
    result = AnomalyPredictionResult(
        component_id=purl,
        anomaly_score=score,
        anomaly_probability=prob,
        classification=classification,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_SCHEMA_VERSION,
        explanation_signals=signals
    )
    
    # Return as dict matching the legacy API signature
    return {
        "anomaly_score": result.anomaly_score,
        "anomaly_probability": round(result.anomaly_probability, 4),
        "classification": result.classification,
        "indicators": [s.description for s in result.explanation_signals],
        "model_version": result.model_version,
    }

def classify_malicious_dependency(component: dict) -> dict:
    """
    Analyzes a component and returns a SuspiciousDependencyResult dict.
    (Note: Kept legacy function name `classify_malicious_dependency` for drop-in replacement,
     but the internal terminology correctly limits scope to Suspicion Scoring per prototype rules).
    """
    purl = component.get("purl", "UNKNOWN")
    features = build_features_vector(component)
    
    prob, classification = compute_suspicion(
        features, 
        model_manager.get_scaler(), 
        model_manager.get_malicious_model()
    )
    
    signals = generate_suspicion_signals(features)
    
    result = SuspiciousDependencyResult(
        component_id=purl,
        probability=prob,
        classification=classification,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_SCHEMA_VERSION,
        explanation_signals=signals
    )
    
    return {
        "classification": result.classification,
        "probability": round(result.probability, 4),
        "contributing_features": [s.feature_name for s in result.explanation_signals],
        "model_version": result.model_version,
    }
