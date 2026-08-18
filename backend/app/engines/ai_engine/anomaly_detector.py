"""
Anomaly Detection Inference.
Responsibility: Uses loaded models to compute an anomaly score, or falls back to rules if unavailable.
"""
from typing import Tuple, List
from backend.app.engines.ai_engine.prediction import ExplanationSignal

def compute_anomaly(features: list, scaler, anomaly_model) -> Tuple[int, float, str]:
    if anomaly_model and scaler:
        try:
            scaled = scaler.transform([features])
            pred = anomaly_model.predict(scaled)[0]           # -1=anomaly, 1=normal
            score_sample = anomaly_model.score_samples(scaled)[0]  # lower = more anomalous
            
            # Normalize to 0-100
            anomaly_score = max(0, min(100, int((0.8 + score_sample) / 0.5 * 100)))
            anomaly_probability = 1.0 - max(0.0, min(1.0, (score_sample + 0.9) / 0.6))
            classification = "HIGH_ANOMALY" if pred == -1 or anomaly_score > 60 else "NORMAL"
            
            return anomaly_score, anomaly_probability, classification
        except Exception as e:
            print(f"[ai_engine.anomaly_detector] Inference error: {e}. Falling back.")
            return _anomaly_heuristic(features)
    
    return _anomaly_heuristic(features)

def _anomaly_heuristic(features: list) -> Tuple[int, float, str]:
    """Rule-based fallback when trained model is unavailable."""
    score = 0
    if features[7] > 0.3: score += 30   # obfuscation
    if features[0] < 30:  score += 25   # very new package
    if features[6] == 1:  score += 15   # install script
    if features[8] > 2:   score += 20   # network calls
    if features[4] == 1:  score += 10   # single maintainer
    
    classification = "HIGH_ANOMALY" if score >= 60 else ("REVIEW" if score >= 40 else "NORMAL")
    return score, score / 100.0, classification

def generate_anomaly_signals(features: list) -> List[ExplanationSignal]:
    signals = []
    if features[7] > 0.3:
        signals.append(ExplanationSignal(
            feature_name="obfuscation_score",
            impact="HIGH",
            description="Elevated code obfuscation index detected."
        ))
    if features[0] < 30:
        signals.append(ExplanationSignal(
            feature_name="age_days",
            impact="HIGH",
            description="Unusually low package age."
        ))
    if features[6] == 1:
        signals.append(ExplanationSignal(
            feature_name="has_install_script",
            impact="MEDIUM",
            description="Contains pre/post installation hooks."
        ))
    if features[8] > 2:
        signals.append(ExplanationSignal(
            feature_name="network_call_count",
            impact="MEDIUM",
            description="Contains system or network utility API calls."
        ))
    if features[4] == 1:
        signals.append(ExplanationSignal(
            feature_name="maintainer_count",
            impact="LOW",
            description="Single developer maintainer structure."
        ))
    return signals

def compute_suspicion(features: list, scaler, malicious_model) -> Tuple[float, str]:
    """
    Suspicious Dependency Detection.
    Note: Prototype avoids term "malicious" detection.
    """
    if malicious_model and scaler:
        try:
            scaled = scaler.transform([features])
            prob = malicious_model.predict_proba(scaled)[0][1]
        except Exception as e:
            print(f"[ai_engine.anomaly_detector] Suspicious classifier error: {e}. Falling back.")
            prob = _suspicious_heuristic(features)
    else:
        prob = _suspicious_heuristic(features)

    level = _prob_to_level(prob)
    return prob, level

def _suspicious_heuristic(features: list) -> float:
    prob = 0.05
    if features[7] > 0.5: prob += 0.40   # obfuscation
    if features[6] == 1:  prob += 0.20   # install script
    if features[8] > 3:   prob += 0.25   # network calls
    if features[0] < 15:  prob += 0.10   # brand new
    return min(prob, 1.0)

def _prob_to_level(prob: float) -> str:
    if prob < 0.2:   return "LOW"
    if prob < 0.5:   return "MEDIUM"
    if prob < 0.8:   return "HIGH"
    return "CRITICAL"

def generate_suspicion_signals(features: list) -> List[ExplanationSignal]:
    signals = []
    if features[7] > 0.3:
        signals.append(ExplanationSignal(feature_name="obfuscation_score", impact="HIGH", description="High obfuscation."))
    if features[6] == 1:
        signals.append(ExplanationSignal(feature_name="has_install_script", impact="MEDIUM", description="Install script found."))
    if features[8] > 2:
        signals.append(ExplanationSignal(feature_name="network_call_count", impact="MEDIUM", description="Network calls found."))
    if features[0] < 30:
        signals.append(ExplanationSignal(feature_name="age_days", impact="LOW", description="Newly published."))
    return signals
