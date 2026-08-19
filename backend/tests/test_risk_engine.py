"""
Tests for the Phase 3 Explainable Risk Scoring Engine.

Verifies:
- Determinism: same input always → same score
- Correct weight application per signal
- Missing signals are recorded, not silently treated as safe
- Unknown exploit gets partial unknown-risk premium, not zero
- Score is capped at 100
- calculation_version is returned
"""
import pytest
from backend.app.engines.risk_engine import (
    prioritize_risk,
    W_CVSS_SEVERITY, W_EXPLOITABILITY, W_DEPENDENCY_IMPACT,
    W_OUTDATED, W_DEPENDENCY_DEPTH, W_ML_ANOMALY,
    CALCULATION_VERSION,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_vuln(cvss=None, severity="HIGH", fixed="4.17.21", known_exploited=False):
    return {
        "cvss_score": cvss,
        "severity": severity,
        "fixed_versions": fixed,
        "known_exploited": known_exploited,
    }

def make_component(direct=True, depth=1):
    return {"name": "test-pkg", "version": "1.0.0", "direct": direct, "depth": depth}


# ── Core determinism ───────────────────────────────────────────────────────────

class TestDeterminism:

    def test_same_input_same_output(self):
        comp = make_component()
        vulns = [make_vuln(cvss=9.8)]
        r1 = prioritize_risk(comp, vulns)
        r2 = prioritize_risk(comp, vulns)
        assert r1["risk_score"] == r2["risk_score"]
        assert r1["factors"] == r2["factors"]
        assert r1["missing_signals"] == r2["missing_signals"]

    def test_calculation_version_returned(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=5.0)])
        assert r["calculation_version"] == CALCULATION_VERSION

    def test_score_capped_at_100(self):
        comp = make_component(direct=True, depth=0)
        vulns = [make_vuln(cvss=10.0, known_exploited=True)]
        r = prioritize_risk(comp, vulns, blast_radius_info={"impact_score": 10, "affected_dependents_count": 10, "production_exposure": True},
                            anomaly_info={"anomaly_score": 99})
        assert r["risk_score"] <= 100


# ── CVSS Signal ───────────────────────────────────────────────────────────────

class TestCVSSSignal:

    def test_critical_cvss_gives_max_cvss_points(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=10.0)])
        cvss_factor = next((f for f in r["factors"] if f["type"] == "CVSS"), None)
        assert cvss_factor is not None
        assert cvss_factor["points"] == W_CVSS_SEVERITY  # 100% weight for CRITICAL

    def test_high_cvss_gives_80pct(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=7.5)])
        cvss_factor = next(f for f in r["factors"] if f["type"] == "CVSS")
        assert cvss_factor["points"] == round(W_CVSS_SEVERITY * 0.80, 1)

    def test_medium_cvss_gives_50pct(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=5.5)])
        cvss_factor = next(f for f in r["factors"] if f["type"] == "CVSS")
        assert cvss_factor["points"] == round(W_CVSS_SEVERITY * 0.50, 1)

    def test_no_vulns_records_missing_signal(self):
        r = prioritize_risk(make_component(), [])
        assert any("CVSS_SCORE" in s for s in r["missing_signals"])

    def test_severity_fallback_when_no_cvss_number(self):
        vuln = {"severity": "CRITICAL", "fixed_versions": "2.0"}
        r = prioritize_risk(make_component(), [vuln])
        cvss_factor = next((f for f in r["factors"] if f["type"] == "CVSS"), None)
        assert cvss_factor is not None
        assert cvss_factor["severity"] == "CRITICAL"


# ── Exploit Signal ─────────────────────────────────────────────────────────────

class TestExploitSignal:

    def test_known_exploit_gives_full_weight(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=7.0, known_exploited=True)])
        exploit_factor = next((f for f in r["factors"] if f["type"] == "EXPLOIT"), None)
        assert exploit_factor is not None
        assert exploit_factor["points"] == W_EXPLOITABILITY

    def test_unknown_exploit_gives_partial_premium(self):
        """Vulns with unknown exploit status must not be treated as safe."""
        r = prioritize_risk(make_component(), [make_vuln(cvss=7.0)])
        exploit_factor = next((f for f in r["factors"] if f["type"] == "EXPLOIT"), None)
        # No known exploit factor — but premium should appear in missing_signals
        assert exploit_factor is None
        assert any("EXPLOIT_STATUS" in s for s in r["missing_signals"])
        # Score should still be above what CVSS alone would give for a HIGH severity
        base_from_cvss = round(W_CVSS_SEVERITY * 0.80, 1)
        assert r["risk_score"] > base_from_cvss


# ── Dependency Signals ─────────────────────────────────────────────────────────

class TestDependencySignals:

    def test_direct_dependency_scores_higher_than_transitive(self):
        vulns = [make_vuln(cvss=7.0)]
        direct_r = prioritize_risk(make_component(direct=True), vulns)
        transitive_r = prioritize_risk(make_component(direct=False), vulns)
        assert direct_r["risk_score"] > transitive_r["risk_score"]

    def test_unknown_direct_records_missing_signal(self):
        comp = {"name": "x", "version": "1.0"}  # no 'direct' key
        r = prioritize_risk(comp, [])
        assert any("DIRECT_DEPENDENCY" in s for s in r["missing_signals"])

    def test_depth_zero_scores_higher_than_depth_four(self):
        vulns = [make_vuln(cvss=7.0)]
        shallow_r = prioritize_risk(make_component(depth=0), vulns)
        deep_r = prioritize_risk(make_component(depth=4), vulns)
        assert shallow_r["risk_score"] >= deep_r["risk_score"]

    def test_blast_radius_adds_points(self):
        vulns = [make_vuln(cvss=7.0)]
        no_blast = prioritize_risk(make_component(), vulns, blast_radius_info=None)
        with_blast = prioritize_risk(make_component(), vulns,
                                     blast_radius_info={"impact_score": 5, "affected_dependents_count": 8, "production_exposure": False})
        assert with_blast["risk_score"] > no_blast["risk_score"]


# ── Outdated Signal ────────────────────────────────────────────────────────────

class TestOutdatedSignal:

    def test_fixed_version_available_adds_points(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=7.0, fixed="4.17.21")])
        outdated_factor = next((f for f in r["factors"] if f["factor"] == "OUTDATED"), None)
        assert outdated_factor is not None
        assert outdated_factor["points"] == W_OUTDATED

    def test_no_fixed_version_records_missing_signal(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=7.0, fixed="")])
        assert any("FIXED_VERSION" in s for s in r["missing_signals"])


# ── ML Anomaly Signal ─────────────────────────────────────────────────────────

class TestMLAnomalySignal:

    def test_high_anomaly_score_adds_points(self):
        r_with = prioritize_risk(make_component(), [make_vuln(cvss=7.0)],
                                 anomaly_info={"anomaly_score": 85})
        r_without = prioritize_risk(make_component(), [make_vuln(cvss=7.0)],
                                    anomaly_info={"anomaly_score": 30})
        assert r_with["risk_score"] > r_without["risk_score"]

    def test_normal_anomaly_no_penalty(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=7.0)],
                            anomaly_info={"anomaly_score": 30})
        anomaly_factor = next((f for f in r["factors"] if f["type"] == "ML_ANOMALY"), None)
        assert anomaly_factor is None  # below threshold — no factor added

    def test_no_anomaly_info_records_missing_signal(self):
        r = prioritize_risk(make_component(), [make_vuln(cvss=7.0)], anomaly_info=None)
        assert any("ML_ANOMALY" in s for s in r["missing_signals"])


# ── Risk Level Thresholds ─────────────────────────────────────────────────────

class TestRiskLevels:

    def test_zero_score_is_low(self):
        from backend.app.engines.risk_engine import _score_to_level
        assert _score_to_level(0) == "LOW"
        assert _score_to_level(29) == "LOW"

    def test_medium_range(self):
        from backend.app.engines.risk_engine import _score_to_level
        assert _score_to_level(30) == "MEDIUM"
        assert _score_to_level(59) == "MEDIUM"

    def test_high_range(self):
        from backend.app.engines.risk_engine import _score_to_level
        assert _score_to_level(60) == "HIGH"
        assert _score_to_level(84) == "HIGH"

    def test_critical_range(self):
        from backend.app.engines.risk_engine import _score_to_level
        assert _score_to_level(85) == "CRITICAL"
        assert _score_to_level(100) == "CRITICAL"
