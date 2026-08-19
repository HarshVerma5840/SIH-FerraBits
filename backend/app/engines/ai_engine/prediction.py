"""
Data Transfer Objects and Schemas for ML Predictions.
Enforces strict schemas for ML outputs so the deterministic engine
does not have to guess what the ML engine returned.
"""
from typing import List
from pydantic import BaseModel, Field

class ExplanationSignal(BaseModel):
    feature_name: str
    impact: str
    description: str

class AnomalyPredictionResult(BaseModel):
    component_id: str = Field(description="Canonical component identifier (PURL)")
    anomaly_score: int = Field(ge=0, le=100, description="Normalized score 0-100")
    anomaly_probability: float = Field(ge=0.0, le=1.0)
    classification: str = Field(description="NORMAL, REVIEW, or HIGH_ANOMALY")
    model_name: str = Field(default="IsolationForest")
    model_version: str
    feature_version: str = Field(default="1.0.0")
    explanation_signals: List[ExplanationSignal]

class SuspiciousDependencyResult(BaseModel):
    component_id: str
    probability: float = Field(ge=0.0, le=1.0)
    classification: str = Field(description="LOW, MEDIUM, HIGH, CRITICAL")
    model_name: str = Field(default="SuspiciousDependencyClassifier")
    model_version: str
    feature_version: str = Field(default="1.0.0")
    explanation_signals: List[ExplanationSignal]
