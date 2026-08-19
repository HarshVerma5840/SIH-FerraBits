"""
AI Engine Facade Service (Phase 5 Prototype).
Responsibility: Provide the single entry point for ML anomaly detection.
In this prototype phase, this uses simple heuristics rather than a trained ML model,
but establishes the `analyze_dependency` interface for future model integration.
"""

def analyze_dependency(component: dict) -> dict:
    """
    Analyzes a component and returns a prototype anomaly prediction result.
    This establishes the interface for future ML model integration.
    """
    score = 0
    signals = []
    
    # Heuristic: Age
    # In a real model, this would be `age_days` from a registry API.
    # We use version_source as a proxy in this prototype (e.g. unknown origin is suspicious)
    if component.get("version_source") not in ["lockfile", "manifest"]:
        score += 15
        signals.append("Unverified version source origin")
        
    # Heuristic: Obfuscation / Hash
    if component.get("hash_sha256", "Unknown") == "Unknown" and component.get("version_source") == "lockfile":
        score += 20
        signals.append("Missing cryptographic integrity hash in lockfile")
        
    # Heuristic: License
    if component.get("license") in ["Unknown", "UNKNOWN", None]:
        score += 15
        signals.append("Unidentified or missing license")
        
    # Heuristic: Depth
    if component.get("depth", 0) > 4:
        score += 10
        signals.append("Deeply nested transitive dependency (depth > 4)")
        
    # Determine classification based on score
    if score >= 60:
        classification = "SUSPICIOUS"
    elif score >= 30:
        classification = "REVIEW"
    else:
        classification = "NORMAL"

    return {
        "anomaly_score": score,
        "classification": classification,
        "signals": signals
    }
