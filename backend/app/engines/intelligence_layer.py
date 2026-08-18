"""
Security Intelligence Layer.
Fetches canonical vulnerability information from external sources (OSV API)
and normalizes results into SBOMGuard's internal format.

Rules:
- Never fabricate CVSS scores.
- CVSS is computed from the official vector string using the CVSS v3.1 formula.
- OSV is the authoritative source; offline_db is a fallback, never a primary.
- Missing information is represented as None / "UNKNOWN".
"""
import time
import math
import requests
import json
from datetime import datetime
from threading import Lock

# In-memory cache: { cache_key: (timestamp, [vuln_list]) }
_osv_cache: dict = {}
_cache_lock = Lock()
CACHE_TTL_SECONDS = 3600  # 1 hour

# ─────────────────────────────────────────────────────────────────────────────
# Ecosystem Mapping
# ─────────────────────────────────────────────────────────────────────────────

def _map_ecosystem_to_osv(ecosystem: str) -> str:
    """Map internal ecosystem names to OSV ecosystem identifiers."""
    eco = ecosystem.lower()
    mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "maven": "Maven",
        "go": "Go",
        "crates": "crates.io",
        "nuget": "NuGet",
        "rubygems": "RubyGems",
        "packagist": "Packagist",
        "hex": "Hex",
    }
    return mapping.get(eco, ecosystem)


# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.x Base Score Calculation
# Source: CVSS v3.1 Specification (https://www.first.org/cvss/v3.1/specification-document)
# Computes the exact base score from a vector string. No guessing.
# ─────────────────────────────────────────────────────────────────────────────

_AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_MAP = {"L": 0.77, "H": 0.44}
_PR_MAP_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_MAP_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_MAP = {"N": 0.85, "R": 0.62}
_CIA_MAP = {"N": 0.00, "L": 0.22, "H": 0.56}


def _cvss3_base_score(vector: str) -> tuple[float | None, str]:
    """
    Parse CVSS v3.x vector string and return (base_score_float, severity_level).
    Returns (None, 'UNKNOWN') if the vector is missing required metrics.
    """
    try:
        if not vector or "/" not in vector:
            return None, "UNKNOWN"

        # Strip prefix like "CVSS:3.1" or "CVSS:3.0"
        parts = vector.split("/")
        metric_parts = [p for p in parts if ":" in p and not p.upper().startswith("CVSS")]

        metrics: dict[str, str] = {}
        for part in metric_parts:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()

        av  = _AV_MAP.get(metrics.get("AV", ""))
        ac  = _AC_MAP.get(metrics.get("AC", ""))
        ui  = _UI_MAP.get(metrics.get("UI", ""))
        s   = metrics.get("S", "")
        c   = _CIA_MAP.get(metrics.get("C", ""))
        i   = _CIA_MAP.get(metrics.get("I", ""))
        a   = _CIA_MAP.get(metrics.get("A", ""))
        pr_raw = metrics.get("PR", "")
        pr  = (_PR_MAP_CHANGED if s == "C" else _PR_MAP_UNCHANGED).get(pr_raw)

        if None in (av, ac, ui, pr, c, i, a) or s not in ("U", "C"):
            return None, "UNKNOWN"

        # ISS (Impact Sub-Score)
        iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

        if s == "U":
            impact = 3.4 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0.0
        elif s == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        # Round up to nearest 0.1 per spec
        base_score = math.ceil(base_score * 10) / 10

        if base_score >= 9.0:
            level = "CRITICAL"
        elif base_score >= 7.0:
            level = "HIGH"
        elif base_score >= 4.0:
            level = "MEDIUM"
        elif base_score > 0.0:
            level = "LOW"
        else:
            level = "NONE"

        return round(base_score, 1), level

    except Exception:
        return None, "UNKNOWN"


def _extract_cvss_severity(vuln_data: dict) -> tuple[float | None, str]:
    """
    Extracts the highest CVSS base score and severity level from an OSV vuln record.
    Tries CVSS_V4 then CVSS_V3.  Never fabricates a score.
    """
    severities = vuln_data.get("severity", [])
    best_score: float | None = None
    best_level = "UNKNOWN"

    for sev in severities:
        sev_type = sev.get("type", "")
        if sev_type in ("CVSS_V3", "CVSS_V4"):
            vector = sev.get("score", "")
            score, level = _cvss3_base_score(vector)
            if score is not None:
                if best_score is None or score > best_score:
                    best_score = score
                    best_level = level

    return best_score, best_level


# ─────────────────────────────────────────────────────────────────────────────
# OSV Response Normalization
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_osv_vuln(v: dict) -> dict:
    """
    Normalize a single OSV vulnerability object into SBOMGuard's internal format.
    Missing fields are represented as None / "UNKNOWN" — never invented.
    """
    vuln_id = v.get("id") or "UNKNOWN"
    aliases = v.get("aliases") or []
    summary = v.get("summary") or v.get("details") or "No description available."

    cvss_score, severity_level = _extract_cvss_severity(v)

    affected_ranges: list[str] = []
    fixed_versions: list[str] = []

    for affected in v.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "introduced" in event:
                    intro = event["introduced"]
                    if intro and intro != "0":
                        affected_ranges.append(f">= {intro}")
                if "fixed" in event and event["fixed"]:
                    fixed_versions.append(event["fixed"])

        # Also include explicit version list if available
        for ver in affected.get("versions", [])[:10]:
            affected_ranges.append(ver)

    # Deduplicate and cap
    fixed_versions = list(dict.fromkeys(fixed_versions))[:5]
    affected_ranges = list(dict.fromkeys(affected_ranges))[:20]

    return {
        "vulnerability_id": vuln_id,
        "aliases": json.dumps(aliases),
        "summary": summary[:1000],
        "cvss_score": cvss_score,
        "severity_level": severity_level if severity_level not in ("NONE", "UNKNOWN") else ("UNKNOWN" if cvss_score is None else "LOW"),
        "affected_versions": json.dumps(affected_ranges),
        "fixed_versions": json.dumps(fixed_versions),
        "known_exploited": False,
        "source": "OSV",
        "source_url": f"https://osv.dev/vulnerability/{vuln_id}",
        "retrieved_at": datetime.utcnow().isoformat()
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def query_osv_vulnerabilities(purl: str, name: str, version: str, ecosystem: str) -> list[dict]:
    """
    Query OSV for a specific package+version.
    Returns normalized vulnerability dicts. Returns [] on network failure.
    """
    if not name or not version or version == "UNKNOWN":
        return []

    cache_key = f"{ecosystem}/{name}@{version}"
    with _cache_lock:
        if cache_key in _osv_cache:
            ts, cached = _osv_cache[cache_key]
            if time.time() - ts < CACHE_TTL_SECONDS:
                return cached

    osv_eco = _map_ecosystem_to_osv(ecosystem)
    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": osv_eco}
    }

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=8.0
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[IntelligenceLayer] OSV query failed for {cache_key}: {exc} — continuing offline.")
        return []

    normalized = [_normalize_osv_vuln(v) for v in data.get("vulns", [])]

    with _cache_lock:
        _osv_cache[cache_key] = (time.time(), normalized)

    return normalized


def query_osv_with_offline_fallback(
    purl: str,
    name: str,
    version: str,
    ecosystem: str,
    offline_db: list[dict],
) -> tuple[list[dict], str]:
    """
    Hybrid lookup: OSV first, offline_db as fallback.

    Returns: (vuln_list, source)
    source: "OSV" | "OFFLINE_DB" | "NONE"
    """
    osv_results = query_osv_vulnerabilities(purl, name, version, ecosystem)
    if osv_results:
        return osv_results, "OSV"

    # Fallback to locally embedded vulnerability database
    from backend.app.engines.security_engine import is_version_affected
    offline_matches: list[dict] = []

    for entry in offline_db:
        if entry.get("package_name") != name:
            continue
        if entry.get("ecosystem") != ecosystem:
            continue
        if not is_version_affected(version, entry.get("affected_versions", "")):
            continue

        cve_id = entry["cve_id"]
        refs = entry.get("references", [])
        offline_matches.append({
            "vulnerability_id": cve_id,
            "aliases": json.dumps([]),
            "summary": entry.get("description", ""),
            "cvss_score": entry.get("cvss_score"),
            "severity_level": entry.get("severity", "UNKNOWN"),
            "affected_versions": json.dumps([entry.get("affected_versions", "")]),
            "fixed_versions": json.dumps([entry.get("fixed_versions", "")] if entry.get("fixed_versions") else []),
            "known_exploited": False,
            "source": "OFFLINE_DB",
            "source_url": refs[0] if refs else None,
            "retrieved_at": datetime.utcnow().isoformat()
        })

    if offline_matches:
        return offline_matches, "OFFLINE_DB"

    return [], "NONE"
