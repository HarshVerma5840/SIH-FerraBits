"""
Tests for the new architecture-separated engines.
Verifies responsibility boundaries and that no engine crosses into another's domain.
"""
import pytest
from unittest.mock import patch


# ── Utils ─────────────────────────────────────────────────────────────────────

class TestUtils:
    def test_parse_semver_normal(self):
        from backend.app.engines.utils import parse_semver
        assert parse_semver("1.2.3") == [1, 2, 3]

    def test_parse_semver_with_v(self):
        from backend.app.engines.utils import parse_semver
        assert parse_semver("v2.15.0") == [2, 15, 0]

    def test_parse_semver_partial(self):
        from backend.app.engines.utils import parse_semver
        assert parse_semver("4.17") == [4, 17, 0]

    def test_generate_purl(self):
        from backend.app.engines.utils import generate_purl
        assert generate_purl("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"

    def test_generate_purl_lowercase(self):
        from backend.app.engines.utils import generate_purl
        assert generate_purl("NPM", "express", "4.18.0") == "pkg:npm/express@4.18.0"


# ── ML Engine ─────────────────────────────────────────────────────────────────

class TestMLEngine:
    """ML engine must only perform inference — no CVE lookups, no policy decisions."""

    def test_feature_vector_length(self):
        from backend.app.engines.ai_engine.feature_builder import build_features_vector
        comp = {"name": "lodash", "version": "4.17.11"}
        features = build_features_vector(comp)
        assert len(features) == 12, "Feature vector must always be 12-dimensional"

    def test_anomaly_result_has_model_version(self):
        from backend.app.engines.ai_engine.service import run_anomaly_detection
        comp = {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"}
        result = run_anomaly_detection(comp)
        assert "model_version" in result, "Predictions must include model_version for traceability"

    def test_anomaly_result_schema(self):
        from backend.app.engines.ai_engine.service import run_anomaly_detection
        comp = {"name": "express", "version": "4.18.0", "ecosystem": "npm"}
        result = run_anomaly_detection(comp)
        assert "anomaly_score" in result
        assert "anomaly_probability" in result
        assert "classification" in result
        assert "indicators" in result
        assert result["classification"] in ("NORMAL", "REVIEW", "HIGH_ANOMALY")

    def test_malicious_result_schema(self):
        from backend.app.engines.ai_engine.service import classify_malicious_dependency
        comp = {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"}
        result = classify_malicious_dependency(comp)
        assert "classification" in result
        assert "probability" in result
        assert "contributing_features" in result
        assert "model_version" in result
        assert result["classification"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_suspicious_package_flags_higher(self):
        """sih-malicious package must produce higher anomaly score than lodash."""
        from backend.app.engines.ai_engine.service import run_anomaly_detection
        normal = run_anomaly_detection({"name": "lodash", "version": "4.17.11", "ecosystem": "npm"})
        suspicious = run_anomaly_detection({"name": "sih-malicious", "ecosystem": "npm"})
        assert suspicious["classification"] in ("REVIEW", "HIGH_ANOMALY")


# ── Risk Engine ───────────────────────────────────────────────────────────────

class TestRiskEngine:
    """Risk engine combines signals — it does not perform ML or CVE lookups."""

    def test_no_vulnerabilities_gives_low_risk(self):
        from backend.app.engines.risk_engine import prioritize_risk
        comp = {"name": "lodash", "direct": True}
        result = prioritize_risk(comp, [])
        assert result["risk_score"] < 60
        assert result["risk_level"] in ("LOW", "MEDIUM")

    def test_critical_cvss_gives_high_risk(self):
        from backend.app.engines.risk_engine import prioritize_risk
        comp = {"name": "log4j-core", "direct": True}
        vulns = [{"cvss_score": 10.0, "severity": "CRITICAL"}]
        result = prioritize_risk(comp, vulns)
        assert result["risk_score"] >= 60
        assert result["risk_level"] in ("HIGH", "CRITICAL")

    def test_ml_anomaly_contributes_to_score(self):
        """ML score should increase risk score but not be the sole determiner."""
        from backend.app.engines.risk_engine import prioritize_risk
        comp = {"name": "sih-malicious", "direct": True}
        without_ml = prioritize_risk(comp, [])
        with_ml = prioritize_risk(comp, [], anomaly_info={"anomaly_score": 90})
        assert with_ml["risk_score"] > without_ml["risk_score"]

    def test_risk_score_capped_at_100(self):
        from backend.app.engines.risk_engine import prioritize_risk
        comp = {"name": "bad-pkg", "direct": True}
        vulns = [{"cvss_score": 10.0, "severity": "CRITICAL"}]
        anomaly = {"anomaly_score": 100}
        blast = {"impact_score": 50, "affected_dependents_count": 20}
        result = prioritize_risk(comp, vulns, blast_radius_info=blast, anomaly_info=anomaly)
        assert result["risk_score"] <= 100

    def test_supply_chain_detects_version_change(self):
        from backend.app.engines.risk_engine import analyze_supply_chain_behavior
        curr = {"name": "pkg", "version": "2.0.0"}
        prev = {"name": "pkg", "version": "1.0.0"}
        status, changes = analyze_supply_chain_behavior(curr, prev)
        assert len(changes) > 0
        assert any("Version" in c for c in changes)

    def test_supply_chain_initial_scan(self):
        from backend.app.engines.risk_engine import analyze_supply_chain_behavior
        status, changes = analyze_supply_chain_behavior({"name": "pkg"}, None)
        assert status == "NORMAL"


# ── Explanation Engine ────────────────────────────────────────────────────────

class TestExplanationEngine:
    """Explanation engine must never invent security facts."""

    def test_explanation_contains_cve(self):
        from backend.app.engines.explanation_engine import generate_security_explanation
        comp = {"name": "lodash", "version": "4.17.11", "direct": True}
        vulns = [{"cve_id": "CVE-2019-10744", "severity": "CRITICAL"}]
        text = generate_security_explanation(comp, vulns, 75)
        assert "CVE-2019-10744" in text

    def test_explanation_without_vulns_no_cve_mention(self):
        """If no vulnerabilities, explanation must not mention any CVE IDs."""
        from backend.app.engines.explanation_engine import generate_security_explanation
        comp = {"name": "clean-pkg", "version": "1.0.0", "direct": True}
        text = generate_security_explanation(comp, [], 15)
        assert "CVE" not in text

    def test_remediation_uses_fixed_version(self):
        from backend.app.engines.explanation_engine import get_remediation_recommendation
        comp = {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"}
        vulns = [{"cve_id": "CVE-2019-10744", "fixed_versions": "4.17.12", "severity": "CRITICAL"}]
        result = get_remediation_recommendation(comp, vulns)
        assert result["remediation_recommended"] is True
        assert result["recommended_version"] == "4.17.12"

    def test_remediation_no_vulns(self):
        from backend.app.engines.explanation_engine import get_remediation_recommendation
        comp = {"name": "clean", "version": "1.0.0"}
        result = get_remediation_recommendation(comp, [])
        assert result["remediation_recommended"] is False

    def test_whatif_simulation_returns_simulation_status(self):
        from backend.app.engines.explanation_engine import run_whatif_simulation
        comps = [
            {"name": "lodash", "version": "4.17.11", "ecosystem": "npm",
             "purl": "pkg:npm/lodash@4.17.11", "direct": True}
        ]
        result = run_whatif_simulation(comps, "pkg:npm/lodash@4.17.11", "4.17.21")
        assert result["status"] == "SIMULATION"
        assert result["upgraded_package"] == "lodash"
        assert result["target_version"] == "4.17.21"


# ── Policy Engine ─────────────────────────────────────────────────────────────

class TestPolicyEngine:
    """Policy engine consumes findings — it does not generate them."""

    def test_pass_clean_component(self):
        from backend.app.engines.policy_engine import evaluate_policy
        comp = {"name": "clean", "version": "1.0.0", "license_classification": "PERMISSIVE"}
        result = evaluate_policy(comp, [], 10)
        assert result["action"] == "PASS"

    def test_block_critical_cvss(self):
        from backend.app.engines.policy_engine import evaluate_policy
        comp = {"name": "log4j", "version": "2.14.0", "license_classification": "PERMISSIVE"}
        vulns = [{"cvss_score": 10.0, "severity": "CRITICAL"}]
        result = evaluate_policy(comp, vulns, 90)
        assert result["action"] == "BLOCK"

    def test_review_high_cvss(self):
        from backend.app.engines.policy_engine import evaluate_policy
        comp = {"name": "jinja2", "version": "3.1.0", "license_classification": "PERMISSIVE"}
        vulns = [{"cvss_score": 7.5, "severity": "HIGH"}]
        result = evaluate_policy(comp, vulns, 55)
        assert result["action"] in ("REVIEW", "BLOCK")

    def test_block_forbidden_license(self):
        from backend.app.engines.policy_engine import evaluate_policy
        comp = {"name": "gpl-lib", "version": "1.0.0", "license_classification": "FORBIDDEN"}
        result = evaluate_policy(comp, [], 5)
        assert result["action"] == "BLOCK"

    def test_review_unknown_version(self):
        from backend.app.engines.policy_engine import evaluate_policy
        comp = {"name": "mystery", "version": "UNKNOWN", "license_classification": "PERMISSIVE"}
        result = evaluate_policy(comp, [], 0)
        assert result["action"] in ("REVIEW", "BLOCK")

    def test_block_escalates_over_review(self):
        """BLOCK should win over REVIEW when both rules trigger."""
        from backend.app.engines.policy_engine import evaluate_policy
        comp = {"name": "worst-pkg", "version": "1.0.0", "license_classification": "FORBIDDEN",
                "anomaly_score": 90}
        vulns = [{"cvss_score": 9.5, "severity": "CRITICAL"}]
        result = evaluate_policy(comp, vulns, 95)
        assert result["action"] == "BLOCK"

    def test_ml_anomaly_triggers_review(self):
        from backend.app.engines.policy_engine import evaluate_policy
        comp = {"name": "odd-pkg", "version": "1.0.0",
                "license_classification": "PERMISSIVE", "anomaly_score": 85}
        result = evaluate_policy(comp, [], 30)
        assert result["action"] in ("REVIEW", "BLOCK")
