"""
Risk Engine - Final Risk Assessment
Responsibility: Combine deterministic security signals, graph context, and ML outputs
into a single structured risk assessment per component.

Boundary rules:
- Does NOT fetch vulnerability data (consumes pre-computed findings).
- Does NOT perform ML inference (receives anomaly_score as a plain number).
- Does NOT enforce policies (outputs risk score/level for policy_engine to consume).
- Does NOT generate SBOM documents.

Architecture rule: ML output is an INPUT to this engine, not the engine itself.
"""
from typing import Optional


def prioritize_risk(
    component: dict,
    vulnerabilities: list[dict],
    blast_radius_info: Optional[dict] = None,
    anomaly_info: Optional[dict] = None,
) -> dict:
    """
    Engine 37: Risk Prioritization Engine.

    Combines:
      - CVSS score from security findings
      - Dependency depth (direct vs transitive)
      - ML anomaly score (input signal, not authoritative)
      - Blast radius impact from graph_engine

    Returns:
      risk_score  : int 0-100
      risk_level  : 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
      reasons     : list[str] - human-readable contributing factors
    """
    base_score = 0.0
    factors: list[dict] = []

    # ── 1. Vulnerability CVSS contribution (max 50 pts) ──────────────────────
    if vulnerabilities:
        cvss_scores = [v["cvss_score"] for v in vulnerabilities if v.get("cvss_score")]
        if cvss_scores:
            max_cvss = max(cvss_scores)
            base_score += max_cvss * 5.0
            sev_level = "CRITICAL" if max_cvss >= 9.0 else "HIGH" if max_cvss >= 7.0 else "WARNING"
            factors.append({
                "type": "CVSS",
                "severity": sev_level,
                "title": "Critical CVSS score" if sev_level == "CRITICAL" else "Elevated CVSS score",
                "description": f"The vulnerability has a maximum CVSS score of {max_cvss}.",
                "evidence": f"CVSS {max_cvss}"
            })
            
            # Check exploit status
            exploited = [v for v in vulnerabilities if v.get("exploit_status") == "KNOWN" or v.get("known_exploited") == True]
            if exploited:
                base_score += 20.0
                factors.append({
                    "type": "EXPLOIT",
                    "severity": "CRITICAL",
                    "title": "Known exploit status",
                    "description": "Security intelligence indicates that exploitation is known in the wild.",
                    "evidence": "Exploit status: KNOWN"
                })
        else:
            # Fallback: use severity strings when CVSS is absent
            severities = [v.get("severity") or v.get("severity_level") for v in vulnerabilities]
            if "CRITICAL" in severities:
                base_score += 45
                factors.append({"type": "CVSS", "severity": "CRITICAL", "title": "Critical severity vulnerability", "description": "A vulnerability rated CRITICAL is present.", "evidence": "Severity: CRITICAL"})
            elif "HIGH" in severities:
                base_score += 35
                factors.append({"type": "CVSS", "severity": "HIGH", "title": "High severity vulnerability", "description": "A vulnerability rated HIGH is present.", "evidence": "Severity: HIGH"})
            elif "MEDIUM" in severities:
                base_score += 20
                factors.append({"type": "CVSS", "severity": "WARNING", "title": "Medium severity vulnerability", "description": "A vulnerability rated MEDIUM is present.", "evidence": "Severity: MEDIUM"})

    # ── 2. Dependency depth (direct = higher exposure, max 15 pts) ───────────
    is_direct = component.get("direct", True)
    if is_direct:
        base_score += 15
        factors.append({
            "type": "EXPOSURE",
            "severity": "HIGH",
            "title": "Direct project dependency",
            "description": "This component is explicitly included by the project, presenting a direct execution path.",
            "evidence": "Direct Dependency"
        })

    # ── 3. ML anomaly signal (input from ml_engine, max 25 pts) ─────────────
    if anomaly_info:
        ml_score = anomaly_info.get("anomaly_score", 0)
        if ml_score > 60:
            added = ml_score * 0.25
            base_score += added
            factors.append({
                "type": "ML_ANOMALY",
                "severity": "WARNING",
                "title": "Supply-chain anomaly detected",
                "description": "The ML model identified an unusual dependency profile.",
                "evidence": f"Anomaly score: {round(ml_score, 1)}"
            })

    # ── 4. Blast radius from graph_engine (max 10 pts) ───────────────────────
    if blast_radius_info:
        impact = blast_radius_info.get("impact_score", 0)
        if impact > 0:
            added = min(impact * 2.5, 10.0)
            base_score += added
            affected = blast_radius_info.get("affected_dependents_count", 0)
            factors.append({
                "type": "BLAST_RADIUS",
                "severity": "HIGH" if affected >= 5 else "WARNING",
                "title": "Large dependency impact",
                "description": "This component is required by multiple other components in the dependency graph.",
                "evidence": f"Used by {affected} components"
            })
            
        if blast_radius_info.get("production_exposure"):
            base_score += 10.0
            factors.append({
                "type": "EXPOSURE",
                "severity": "HIGH",
                "title": "Production execution path",
                "description": "The affected component is associated with production dependencies.",
                "evidence": "Environment: PRODUCTION"
            })

    final_score = round(min(base_score, 100))
    level = _score_to_level(final_score)

    return {
        "risk_score": final_score,
        "risk_level": level,
        "factors": factors,
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
