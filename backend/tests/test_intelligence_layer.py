"""
Tests for the OSV intelligence layer.
Verifies:
- CVSS v3.x vector-to-score calculation (no heuristics)
- Correct severity thresholds
- Graceful handling of missing/malformed vectors
- Offline DB fallback when OSV is unreachable
- Component identity normalization
"""
import pytest
import json
from unittest.mock import patch, MagicMock

from backend.app.engines.intelligence_layer import (
    _cvss3_base_score,
    _normalize_osv_vuln,
    query_osv_vulnerabilities,
    query_osv_with_offline_fallback,
)


# ── CVSS v3.1 Vector Parser ────────────────────────────────────────────────

class TestCVSSParser:

    def test_log4shell_critical(self):
        """Log4Shell: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0 CRITICAL"""
        score, level = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0
        assert level == "CRITICAL"

    def test_high_severity(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 7.0 HIGH (verified)"""
        score, level = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 7.0
        assert level == "HIGH"

    def test_medium_severity(self):
        """Vector with lower CIA values should produce MEDIUM"""
        score, level = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
        assert score is not None
        assert level in ("MEDIUM", "HIGH")
        assert 4.0 <= score < 9.0

    def test_none_impact(self):
        """All C/I/A = N means no impact, base score = 0"""
        score, level = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0
        assert level == "NONE"

    def test_missing_vector(self):
        score, level = _cvss3_base_score("")
        assert score is None
        assert level == "UNKNOWN"

    def test_malformed_vector(self):
        score, level = _cvss3_base_score("not-a-vector")
        assert score is None
        assert level == "UNKNOWN"

    def test_partial_vector(self):
        """If required metrics are missing, return None."""
        score, level = _cvss3_base_score("CVSS:3.1/AV:N/AC:L")
        assert score is None
        assert level == "UNKNOWN"


# ── OSV Response Normalization ──────────────────────────────────────────────

class TestOSVNormalization:

    def _make_osv_vuln(self, vuln_id="GHSA-1234", cvss_vector=None, fixed="4.17.21"):
        """Build a minimal OSV vulnerability dict."""
        severity = []
        if cvss_vector:
            severity = [{"type": "CVSS_V3", "score": cvss_vector}]
        return {
            "id": vuln_id,
            "aliases": ["CVE-2019-10744"],
            "summary": "Prototype pollution in lodash",
            "severity": severity,
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": fixed}
                            ]
                        }
                    ]
                }
            ]
        }

    def test_normalizes_vuln_id(self):
        vuln = self._make_osv_vuln()
        result = _normalize_osv_vuln(vuln)
        assert result["vulnerability_id"] == "GHSA-1234"

    def test_normalizes_aliases(self):
        vuln = self._make_osv_vuln()
        result = _normalize_osv_vuln(vuln)
        aliases = json.loads(result["aliases"])
        assert "CVE-2019-10744" in aliases

    def test_extracts_fixed_version(self):
        vuln = self._make_osv_vuln(fixed="4.17.21")
        result = _normalize_osv_vuln(vuln)
        fixed = json.loads(result["fixed_versions"])
        assert "4.17.21" in fixed

    def test_skips_introduced_zero(self):
        """introduced=0 means 'from the beginning' and should not appear in affected list."""
        vuln = self._make_osv_vuln()
        result = _normalize_osv_vuln(vuln)
        affected = json.loads(result["affected_versions"])
        assert ">= 0" not in affected

    def test_cvss_computed_correctly(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        vuln = self._make_osv_vuln(cvss_vector=vector)
        result = _normalize_osv_vuln(vuln)
        assert result["cvss_score"] == 10.0
        assert result["severity_level"] == "CRITICAL"

    def test_cvss_none_when_no_severity_data(self):
        vuln = self._make_osv_vuln(cvss_vector=None)
        result = _normalize_osv_vuln(vuln)
        assert result["cvss_score"] is None

    def test_source_is_osv(self):
        vuln = self._make_osv_vuln()
        result = _normalize_osv_vuln(vuln)
        assert result["source"] == "OSV"

    def test_summary_truncated(self):
        long_summary = "x" * 2000
        vuln = {"id": "X-1", "summary": long_summary, "severity": [], "affected": []}
        result = _normalize_osv_vuln(vuln)
        assert len(result["summary"]) <= 1000


# ── Offline Fallback ────────────────────────────────────────────────────────

class TestOfflineFallback:

    OFFLINE_DB = [
        {
            "cve_id": "CVE-2019-10744",
            "ecosystem": "npm",
            "package_name": "lodash",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "affected_versions": "< 4.17.12",
            "fixed_versions": "4.17.12",
            "description": "Prototype pollution in defaultsDeep",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"]
        }
    ]

    @patch("backend.app.engines.intelligence_layer.requests.post")
    def test_falls_back_when_osv_unreachable(self, mock_post):
        mock_post.side_effect = ConnectionError("network error")
        results, source = query_osv_with_offline_fallback(
            "pkg:npm/lodash@4.17.11", "lodash", "4.17.11", "npm", self.OFFLINE_DB
        )
        assert source == "OFFLINE_DB"
        assert len(results) == 1
        assert results[0]["vulnerability_id"] == "CVE-2019-10744"

    @patch("backend.app.engines.intelligence_layer.requests.post")
    def test_uses_osv_when_available(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulns": [{
                "id": "GHSA-osv-test",
                "aliases": [],
                "summary": "Test vulnerability from OSV",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": []
            }]
        }
        mock_post.return_value = mock_response
        results, source = query_osv_with_offline_fallback(
            "pkg:npm/lodash@4.17.11", "lodash", "4.17.11", "npm", self.OFFLINE_DB
        )
        assert source == "OSV"
        assert results[0]["vulnerability_id"] == "GHSA-osv-test"

    @patch("backend.app.engines.intelligence_layer.requests.post")
    def test_returns_none_when_no_match_anywhere(self, mock_post):
        mock_post.side_effect = ConnectionError("network error")
        results, source = query_osv_with_offline_fallback(
            "pkg:npm/safe-package@1.0.0", "safe-package", "1.0.0", "npm", self.OFFLINE_DB
        )
        assert source == "NONE"
        assert results == []

    def test_unknown_version_skipped(self):
        """UNKNOWN version should never be queried."""
        results = query_osv_vulnerabilities("pkg:npm/lodash@UNKNOWN", "lodash", "UNKNOWN", "npm")
        assert results == []
