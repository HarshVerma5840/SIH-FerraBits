"""
Risk Engine — Explainable Deterministic Risk Scoring
Responsibility: Combine security signals into a reproducible 0-100 risk score where
every point of the final score is traceable to a named contributing factor.

Architecture rules (Phase 3):
  - NO ML training or probabilistic inference performed here.
  - Every signal that contributes to the score is recorded in `factors`.
  - Every signal that was *unavailable* is recorded in `missing_signals`.
  - Unknown information is NEVER silently treated as safe.
  - Score is deterministic: same inputs → same score every time.
  - Weights are declared as module-level constants so they can be audited.

Score Breakdown (max 100):
  ┌─────────────────────────────┬──────────┐
  │ Signal                      │ Max pts  │
  ├─────────────────────────────┼──────────┤
  │ CVSS severity               │ 40       │
  │ Exploitability / exploit    │ 20       │
  │ Dependency impact           │ 15       │
  │ Outdated status             │ 10       │
  │ Dependency depth            │  5       │
  │ ML anomaly signal           │ 10       │
  └─────────────────────────────┴──────────┘
  Total max                     │ 100

Calculation version: prototype-v1
"""
from typing import Optional

# ─── Weight constants (audit-visible) ────────────────────────────────────────
W_CVSS_SEVERITY       = 40
W_EXPLOITABILITY      = 20
W_DEPENDENCY_IMPACT   = 15
W_OUTDATED            = 10
W_DEPENDENCY_DEPTH    =  5
W_ML_ANOMALY          = 10

CALCULATION_VERSION = "prototype-v1"

# CVSS → fraction of W_CVSS_SEVERITY to award
# 0.0 – 3.9 → LOW, 4.0 – 6.9 → MEDIUM, 7.0 – 8.9 → HIGH, 9.0 – 10.0 → CRITICAL
def _cvss_fraction(cvss: float) -> float:
    if cvss >= 9.0:  return 1.00
    if cvss >= 7.0:  return 0.80
    if cvss >= 4.0:  return 0.50
    return 0.20


def prioritize_risk(
    component: dict,
    vulnerabilities: list[dict],
    blast_radius_info: Optional[dict] = None,
    anomaly_info: Optional[dict] = None,
) -> dict:
    """
    Weighted deterministic risk scoring engine (Phase 3 — Explainable Risk Analysis).

    Args:
        component        : Component dict from discovery engine
        vulnerabilities  : List of CVE dicts (may be from OFFLINE_VULN_DB or OSV)
        blast_radius_info: Graph impact data from graph_engine (optional)
        anomaly_info     : ML anomaly result dict (optional)

    Returns:
        {
            risk_score         : int 0-100
            risk_level         : 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
            factors            : list[dict]  — every contributing signal
            missing_signals    : list[str]   — signals not available (never silently safe)
            calculation_version: str
        }
    """
    score = 0.0
    factors: list[dict] = []
    missing_signals: list[str] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Signal 1: CVSS Severity  (max W_CVSS_SEVERITY = 40 pts)
    # ─────────────────────────────────────────────────────────────────────────
    cvss_scores = [
        v.get("cvss_score") or v.get("cvss")
        for v in vulnerabilities
        if (v.get("cvss_score") or v.get("cvss")) is not None
    ]
    if cvss_scores:
        max_cvss = max(cvss_scores)
        frac = _cvss_fraction(max_cvss)
        pts = round(W_CVSS_SEVERITY * frac, 1)
        score += pts

        severity_label = (
            "CRITICAL" if max_cvss >= 9.0 else
            "HIGH"     if max_cvss >= 7.0 else
            "MEDIUM"   if max_cvss >= 4.0 else
            "LOW"
        )
        factors.append({
            "factor":      "CVSS_SEVERITY",
            "type":        "CVSS",
            "severity":    severity_label,
            "title":       f"{severity_label} CVSS Score ({max_cvss})",
            "description": f"The highest CVSS score across all known vulnerabilities is {max_cvss}.",
            "evidence":    f"CVSS {max_cvss}",
            "points":      pts,
            "max_points":  W_CVSS_SEVERITY,
        })
    else:
        # If there are vulns but no CVSS, fall back to severity strings
        severities = [
            (v.get("severity") or v.get("severity_level") or "").upper()
            for v in vulnerabilities
        ]
        if "CRITICAL" in severities:
            pts = round(W_CVSS_SEVERITY * 1.00, 1)
            score += pts
            factors.append({
                "factor": "CVSS_SEVERITY", "type": "CVSS", "severity": "CRITICAL",
                "title": "Critical Severity (no CVSS vector)",
                "description": "A vulnerability rated CRITICAL is present; no CVSS numeric score was available.",
                "evidence": "Severity: CRITICAL", "points": pts, "max_points": W_CVSS_SEVERITY,
            })
        elif "HIGH" in severities:
            pts = round(W_CVSS_SEVERITY * 0.80, 1)
            score += pts
            factors.append({
                "factor": "CVSS_SEVERITY", "type": "CVSS", "severity": "HIGH",
                "title": "High Severity (no CVSS vector)",
                "description": "A vulnerability rated HIGH is present; no CVSS numeric score was available.",
                "evidence": "Severity: HIGH", "points": pts, "max_points": W_CVSS_SEVERITY,
            })
        elif "MEDIUM" in severities:
            pts = round(W_CVSS_SEVERITY * 0.50, 1)
            score += pts
            factors.append({
                "factor": "CVSS_SEVERITY", "type": "CVSS", "severity": "MEDIUM",
                "title": "Medium Severity (no CVSS vector)",
                "description": "A vulnerability rated MEDIUM is present; no CVSS numeric score was available.",
                "evidence": "Severity: MEDIUM", "points": pts, "max_points": W_CVSS_SEVERITY,
            })
        elif vulnerabilities:
            missing_signals.append("CVSS_SCORE: Vulnerabilities exist but no CVSS or severity data is available.")
        else:
            missing_signals.append("CVSS_SCORE: No vulnerabilities detected — CVSS signal unavailable.")

    # ─────────────────────────────────────────────────────────────────────────
    # Signal 2: Exploitability / Known Exploit  (max W_EXPLOITABILITY = 20 pts)
    # ─────────────────────────────────────────────────────────────────────────
    known_exploited = [
        v for v in vulnerabilities
        if v.get("exploit_status") == "KNOWN" or v.get("known_exploited") is True
    ]
    if known_exploited:
        pts = float(W_EXPLOITABILITY)
        score += pts
        factors.append({
            "factor":      "KNOWN_EXPLOIT",
            "type":        "EXPLOIT",
            "severity":    "CRITICAL",
            "title":       "Known Active Exploit",
            "description": "Security intelligence confirms that this vulnerability is actively exploited in the wild.",
            "evidence":    f"exploit_status=KNOWN on {len(known_exploited)} finding(s)",
            "points":      pts,
            "max_points":  W_EXPLOITABILITY,
        })
    elif vulnerabilities:
        # Vulns exist but no exploit data — partial score (25 % of weight as unknown-risk premium)
        pts = round(W_EXPLOITABILITY * 0.25, 1)
        score += pts
        missing_signals.append(
            "EXPLOIT_STATUS: Exploit status is unknown for all findings — "
            f"applying {pts}pt unknown-risk premium instead of treating as safe."
        )
    else:
        missing_signals.append("EXPLOIT_STATUS: No vulnerabilities — exploit signal not applicable.")

    # ─────────────────────────────────────────────────────────────────────────
    # Signal 3: Dependency Impact  (max W_DEPENDENCY_IMPACT = 15 pts)
    # Split: direct dependency (10 pts) + blast radius (5 pts)
    # ─────────────────────────────────────────────────────────────────────────
    is_direct = component.get("direct", None)
    if is_direct is True:
        pts = round(W_DEPENDENCY_IMPACT * 0.70, 1)
        score += pts
        factors.append({
            "factor":      "DIRECT_DEPENDENCY",
            "type":        "EXPOSURE",
            "severity":    "HIGH",
            "title":       "Direct Project Dependency",
            "description": "The component is explicitly listed in the project manifest, creating a direct execution path.",
            "evidence":    "direct=True",
            "points":      pts,
            "max_points":  round(W_DEPENDENCY_IMPACT * 0.70, 1),
        })
    elif is_direct is False:
        # Transitive — lower exposure but still record it
        pts = round(W_DEPENDENCY_IMPACT * 0.20, 1)
        score += pts
        factors.append({
            "factor":      "TRANSITIVE_DEPENDENCY",
            "type":        "EXPOSURE",
            "severity":    "LOW",
            "title":       "Transitive Dependency",
            "description": "The component is introduced transitively through a parent package.",
            "evidence":    "direct=False",
            "points":      pts,
            "max_points":  round(W_DEPENDENCY_IMPACT * 0.70, 1),
        })
    else:
        missing_signals.append("DIRECT_DEPENDENCY: Dependency relationship (direct/transitive) is unknown.")

    if blast_radius_info:
        affected = blast_radius_info.get("affected_dependents_count", 0)
        impact = blast_radius_info.get("impact_score", 0)
        if affected > 0 or impact > 0:
            blast_pts = round(min(W_DEPENDENCY_IMPACT * 0.30 * (min(affected, 10) / 10.0), W_DEPENDENCY_IMPACT * 0.30), 1)
            score += blast_pts
            factors.append({
                "factor":      "HIGH_BLAST_RADIUS",
                "type":        "BLAST_RADIUS",
                "severity":    "HIGH" if affected >= 5 else "MEDIUM",
                "title":       f"Blast Radius: {affected} Downstream Components",
                "description": "If compromised, this component could affect multiple downstream dependencies.",
                "evidence":    f"Affects {affected} component(s) with graph impact_score={impact}",
                "points":      blast_pts,
                "max_points":  round(W_DEPENDENCY_IMPACT * 0.30, 1),
            })
        if blast_radius_info.get("production_exposure"):
            factors.append({
                "factor":      "PRODUCTION_EXPOSURE",
                "type":        "EXPOSURE",
                "severity":    "HIGH",
                "title":       "Production Execution Path",
                "description": "The component is in the production dependency chain.",
                "evidence":    "production_exposure=True",
                "points":      0,  # already captured in blast radius — additive label only
                "max_points":  0,
            })
    else:
        missing_signals.append("BLAST_RADIUS: Graph data unavailable — downstream impact not assessed.")

    # ─────────────────────────────────────────────────────────────────────────
    # Signal 4: Outdated Status (max W_OUTDATED = 10 pts)
    # A fix being available with an unchanged old version is the "outdated" signal.
    # ─────────────────────────────────────────────────────────────────────────
    fixed_versions = []
    for v in vulnerabilities:
        fv = v.get("fixed_versions") or v.get("fixed_version") or ""
        if isinstance(fv, str):
            # Could be JSON-encoded list or plain string
            try:
                import json
                parsed = json.loads(fv)
                if isinstance(parsed, list):
                    fixed_versions.extend(parsed)
                else:
                    fixed_versions.append(str(parsed))
            except Exception:
                if fv:
                    fixed_versions.append(fv)
        elif isinstance(fv, list):
            fixed_versions.extend(fv)

    fixed_versions = [v for v in fixed_versions if v and v.strip()]
    if fixed_versions:
        pts = float(W_OUTDATED)
        score += pts
        factors.append({
            "factor":      "OUTDATED",
            "type":        "VERSION",
            "severity":    "MEDIUM",
            "title":       "Fixed Version Available",
            "description": "A patched version exists but has not been applied.",
            "evidence":    f"Fixed in: {', '.join(fixed_versions[:3])}",
            "points":      pts,
            "max_points":  W_OUTDATED,
        })
    elif vulnerabilities:
        # Vuln exists but no fix known — partially penalise (no safe assumption)
        pts = round(W_OUTDATED * 0.50, 1)
        score += pts
        missing_signals.append(
            f"FIXED_VERSION: No fixed version is currently known for the reported vulnerabilities — "
            f"applying {pts}pt unresolved-risk premium."
        )
    else:
        missing_signals.append("FIXED_VERSION: No vulnerabilities — outdated signal not applicable.")

    # ─────────────────────────────────────────────────────────────────────────
    # Signal 5: Dependency Depth  (max W_DEPENDENCY_DEPTH = 5 pts)
    # Shallow depth (0 or 1) = higher exposure
    # ─────────────────────────────────────────────────────────────────────────
    depth = component.get("depth", None)
    if depth is not None:
        try:
            depth_int = int(depth)
            # depth 0 = project itself (rare), 1 = direct, >1 = transitive
            depth_pts = round(W_DEPENDENCY_DEPTH * max(0.0, 1.0 - (depth_int * 0.25)), 1)
            score += depth_pts
            factors.append({
                "factor":      "DEPENDENCY_DEPTH",
                "type":        "DEPTH",
                "severity":    "HIGH" if depth_int <= 1 else "LOW",
                "title":       f"Dependency Depth: {depth_int}",
                "description": f"Shallower depth means more direct execution exposure (depth {depth_int}).",
                "evidence":    f"depth={depth_int}",
                "points":      depth_pts,
                "max_points":  W_DEPENDENCY_DEPTH,
            })
        except (ValueError, TypeError):
            missing_signals.append("DEPENDENCY_DEPTH: Depth value is non-numeric — signal skipped.")
    else:
        missing_signals.append("DEPENDENCY_DEPTH: Dependency depth information was not recorded.")

    # ─────────────────────────────────────────────────────────────────────────
    # Signal 6: ML Anomaly  (max W_ML_ANOMALY = 10 pts)
    # Only applied when anomaly_score > 60 to avoid noise for normal packages.
    # ─────────────────────────────────────────────────────────────────────────
    if anomaly_info:
        ml_score = anomaly_info.get("anomaly_score", None)
        if ml_score is not None:
            if ml_score > 60:
                # Scale proportionally above the 60-point threshold
                pts = round(W_ML_ANOMALY * ((ml_score - 60) / 40.0), 1)
                pts = min(pts, float(W_ML_ANOMALY))
                score += pts
                factors.append({
                    "factor":      "ANOMALY",
                    "type":        "ML_ANOMALY",
                    "severity":    "CRITICAL" if ml_score > 85 else "HIGH" if ml_score > 70 else "MEDIUM",
                    "title":       "Supply-Chain Anomaly Detected",
                    "description": "The ML anomaly detector flagged this component as unusual relative to its dependency peer group.",
                    "evidence":    f"anomaly_score={round(ml_score, 1)} (threshold >60)",
                    "points":      pts,
                    "max_points":  W_ML_ANOMALY,
                })
            # else: normal ML score — no penalty, but also no missing signal (data was available)
        else:
            missing_signals.append("ML_ANOMALY: Anomaly detection result was present but score was null.")
    else:
        missing_signals.append("ML_ANOMALY: ML anomaly detection result was not provided — signal unavailable.")

    # ─────────────────────────────────────────────────────────────────────────
    # Final score
    # ─────────────────────────────────────────────────────────────────────────
    final_score = round(min(score, 100.0))
    level = _score_to_level(final_score)

    return {
        "risk_score":          final_score,
        "risk_level":          level,
        "factors":             factors,
        "missing_signals":     missing_signals,
        "calculation_version": CALCULATION_VERSION,
    }


def analyze_supply_chain_behavior(
    current_component: dict,
    previous_component: Optional[dict],
) -> tuple[str, list[str]]:
    """
    Engine 38: Supply Chain Behavioral Analysis.

    Compares the same component between two consecutive scans to identify
    unexpected changes that may indicate a supply chain compromise.

    Returns:
      status  : 'NORMAL' | 'SUSPICIOUS' | 'HIGH RISK'
      changes : list[str] - detected behavioural changes
    """
    if not previous_component:
        return "NORMAL", ["Initial scan profile established"]

    changes: list[str] = []

    # Version drift
    curr_v, prev_v = current_component.get("version"), previous_component.get("version")
    if curr_v != prev_v:
        changes.append(f"Version changed from {prev_v} to {curr_v}")

    # License change
    curr_lic = current_component.get("license")
    prev_lic = previous_component.get("license")
    if curr_lic != prev_lic:
        changes.append(f"License modified from '{prev_lic}' to '{curr_lic}'")

    # Maintainer drop to single-maintainer
    curr_m = current_component.get("maintainer_count", 3)
    prev_m = previous_component.get("maintainer_count", 3)
    if curr_m < prev_m and curr_m == 1:
        changes.append(f"Maintainers reduced from {prev_m} to single maintainer")

    # New install hooks
    if current_component.get("has_install_script") and not previous_component.get("has_install_script"):
        changes.append("Pre/post installation hooks introduced in new version")

    if len(changes) >= 2:
        status = "HIGH RISK"
    elif len(changes) == 1:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    return status, changes


# ── Internal helpers ──────────────────────────────────────────────────────────

def _score_to_level(score: int) -> str:
    if score < 30:  return "LOW"
    if score < 60:  return "MEDIUM"
    if score < 85:  return "HIGH"
    return "CRITICAL"
