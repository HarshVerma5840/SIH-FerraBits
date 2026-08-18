import pytest
import os
from unittest.mock import patch, MagicMock
from backend.app.engines.ai_engine.llm_explanation import (
    explain_finding,
    is_llm_available,
    _deterministic_fallback,
    _explanation_cache,
)

@pytest.fixture(autouse=True)
def clear_cache():
    _explanation_cache.clear()
    yield
    _explanation_cache.clear()

def test_deterministic_fallback():
    finding = {
        "component": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
        "vulnerability": {
            "id": "CVE-TEST",
            "severity": "HIGH",
            "cvss": 7.5,
            "fixed_versions": ["4.17.21"],
            "summary": "Prototype pollution"
        },
        "risk_context": {"risk_score": 85}
    }
    result = _deterministic_fallback(finding)
    
    assert "CVE-TEST" in result["summary"]
    assert "lodash" in result["why_it_matters"]
    assert result["technical_explanation"] == "Prototype pollution"
    assert "Upgrade lodash to 4.17.21" in result["recommended_action"]
    assert result["upgrade_target"] == "4.17.21"
    assert result["generated_by"] == "DETERMINISTIC_FALLBACK"
    assert result["confidence"] == "HIGH"

def test_deterministic_fallback_no_fix():
    finding = {
        "component": {"name": "lodash", "version": "4.17.20"},
        "vulnerability": {"id": "CVE-TEST", "severity": "MEDIUM", "fixed_versions": []}
    }
    result = _deterministic_fallback(finding)
    
    assert result["upgrade_target"] is None
    assert "No fixed version is currently known" in result["recommended_action"]
    assert result["confidence"] == "LOW"

@patch("backend.app.engines.ai_engine.llm_explanation.os.environ.get")
@patch("backend.app.engines.ai_engine.llm_explanation._call_gemini")
def test_explain_finding_falls_back_when_no_api_key(mock_gemini, mock_env):
    mock_env.return_value = ""  # No API key
    
    finding = {
        "component": {"name": "test-pkg"},
        "vulnerability": {"id": "CVE-123"}
    }
    
    result = explain_finding(finding)
    assert not mock_gemini.called
    assert result["generated_by"] == "DETERMINISTIC_FALLBACK"

@patch("backend.app.engines.ai_engine.llm_explanation.os.environ.get")
@patch("backend.app.engines.ai_engine.llm_explanation._call_gemini")
def test_explain_finding_uses_gemini_when_available(mock_gemini, mock_env):
    mock_env.return_value = "fake-key"
    mock_gemini.return_value = {
        "summary": "AI summary",
        "generated_by": "GEMINI"
    }
    
    finding = {
        "component": {"name": "test-pkg"},
        "vulnerability": {"id": "CVE-123"}
    }
    
    result = explain_finding(finding)
    assert mock_gemini.called
    assert result["generated_by"] == "GEMINI"
    assert result["summary"] == "AI summary"

@patch("backend.app.engines.ai_engine.llm_explanation.os.environ.get")
@patch("backend.app.engines.ai_engine.llm_explanation._call_gemini")
def test_explain_finding_caches_result(mock_gemini, mock_env):
    mock_env.return_value = "fake-key"
    mock_gemini.return_value = {"summary": "AI summary", "generated_by": "GEMINI"}
    
    finding = {"component": {"name": "test-pkg"}, "vulnerability": {"id": "CVE-123"}}
    
    # First call hits LLM
    result1 = explain_finding(finding)
    assert mock_gemini.call_count == 1
    
    # Second call hits cache
    result2 = explain_finding(finding)
    assert mock_gemini.call_count == 1
    assert result1 == result2
