"""
Explanation Engine — Human-Readable Security Explanations & Remediation
Responsibility: Convert structured security/risk findings into understandable text.
Provides remediation recommendations and what-if impact simulation.

Boundary rules:
- Does NOT change, override, or invent risk scores.
- Does NOT declare vulnerabilities without structured evidence from other engines.
- Does NOT override policy decisions.
- All explanations are derived ONLY from data passed in as arguments.

Critical rule: This engine translates facts — it does not create them.
"""
from typing import Optional
from .utils import parse_semver, generate_purl
from .security_engine import is_version_affected, OFFLINE_VULN_DB
from .risk_engine import prioritize_risk


# ── Security Explanation ──────────────────────────────────────────────────────

def generate_security_explanation(
    component: dict,
    vulnerabilities: list[dict],
    risk_score: int,
    blast_radius_info: Optional[dict] = None,
) -> str:
    """
    Engine 39: Security Explanation Generator.

    Produces a plain-English explanation of WHY a component is flagged.
    All facts are sourced exclusively from the structured inputs — nothing is invented.

    Args:
        component        : Component dict from discovery engine
        vulnerabilities  : List of CVE findings from security_engine
        risk_score       : Final score from risk_engine (0–100)
        blast_radius_info: Graph impact data from graph_engine (optional)

    Returns:
        str — human-readable risk explanation
    """
    name = component["name"]
    version = component.get("version", "unknown")
    is_direct = component.get("direct", True)

    text = (
        f"Package '{name}' (v{version}) is flagged with a {risk_score}/100 "
        f"security threat level. "
    )

    if vulnerabilities:
        cves = [v["cve_id"] for v in vulnerabilities]
        text += f"It contains known vulnerabilities: {', '.join(cves)}. "

    if is_direct:
        text += (
            "As a direct dependency, it is imported directly into the application "
            "namespace, increasing exploitability risk. "
        )
    else:
        text += (
            "It is introduced transitively through parent packages, which can "
            "obscure it from standard dependency scans. "
        )

    if blast_radius_info and blast_radius_info.get("impact_score", 0) > 0:
        affected = blast_radius_info.get("affected_dependents_count", 0)
        text += (
            f"If compromised, this vulnerability's blast radius could propagate "
            f"downstream to affect {affected} other packages in the project tree."
        )

    return text


# ── Remediation Recommendation ────────────────────────────────────────────────

def get_remediation_recommendation(
    component: dict,
    vulnerabilities: list[dict],
) -> dict:
    """
    Engine 40: Remediation Recommendation Generator.

    Recommends the safest upgrade path based on the fixed_versions field
    from security findings. Does NOT invent or guess version numbers.

    Returns:
        remediation_recommended : bool
        current_version         : str
        recommended_version     : str | None
        explanation             : str
        upgrade_impact          : str
    """
    if not vulnerabilities:
        return {
            "remediation_recommended": False,
            "current_version": component.get("version"),
            "recommended_version": None,
            "explanation": "No upgrade required.",
            "upgrade_impact": None,
        }

    current_version = component.get("version")

    # Collect all fixed versions from the matched CVE findings
    fixed_versions = [
        v["fixed_versions"]
        for v in vulnerabilities
        if v.get("fixed_versions") and v["fixed_versions"] != "UNKNOWN"
    ]

    recommended = None
    if fixed_versions:
        # Pick the highest fixed version (ensures all CVEs are resolved)
        recommended = sorted(fixed_versions, key=lambda x: parse_semver(x))[-1]

    if recommended:
        explanation = (
            f"Upgrade {component['name']} to version {recommended} to resolve "
            f"all matched CVE vulnerability disclosures."
        )
        impact = (
            "Minor library code signature adjustments may be needed. "
            "Regression testing of downstream dependents is recommended."
        )
    else:
        recommended = "UNKNOWN"
        explanation = (
            f"No official vendor patch has been released for the identified CVEs. "
            f"Consider migrating to a secure alternative or applying virtual patches."
        )
        impact = "Requires developer manual architecture analysis."

    return {
        "remediation_recommended": True,
        "current_version": current_version,
        "recommended_version": recommended,
        "explanation": explanation,
        "upgrade_impact": impact,
    }


# ── What-If Simulator ─────────────────────────────────────────────────────────

def run_whatif_simulation(
    components: list[dict],
    upgrade_purl: str,
    target_version: str,
    vulnerability_db_list: Optional[list[dict]] = None,
) -> dict:
    """
    Engine 41: What-If Risk Simulator.

    Answers: "What is the projected security posture if I upgrade package X to vY?"

    Process:
      1. Clone component list, apply hypothetical version upgrade
      2. Re-run vulnerability matching against known CVE database
      3. Re-calculate risk scores using risk_engine
      4. Return projected metrics — clearly labelled as SIMULATION output

    Args:
        components          : Current list of component dicts
        upgrade_purl        : PURL of the component to upgrade
        target_version      : Hypothetical target version string
        vulnerability_db_list: CVE database to match against (defaults to OFFLINE_VULN_DB)

    Returns:
        status                     : 'SIMULATION'
        upgraded_package           : str
        target_version             : str
        projected_total_risk       : int
        projected_vulnerability_count: int
        projected_critical_count   : int
        projected_high_count       : int
    """
    vuln_db = vulnerability_db_list or OFFLINE_VULN_DB

    # 1. Clone components and apply the hypothetical upgrade
    simulated: list[dict] = []
    upgrade_name = None

    for c in components:
        comp_copy = dict(c)
        if comp_copy["purl"] == upgrade_purl:
            comp_copy["version"] = target_version
            comp_copy["purl"] = generate_purl(comp_copy["ecosystem"], comp_copy["name"], target_version)
            upgrade_name = comp_copy["name"]
        simulated.append(comp_copy)

    # 2. Re-run vulnerability matching on simulated state
    for c in simulated:
        c_vulns = [
            vuln for vuln in vuln_db
            if vuln["package_name"] == c["name"]
            and vuln["ecosystem"] == c["ecosystem"]
            and is_version_affected(c["version"], vuln["affected_versions"])
        ]
        c["vulnerabilities"] = c_vulns

    # 3. Re-calculate risk scores
    total_risk = 0
    vuln_count = 0
    critical_count = 0
    high_count = 0

    for c in simulated:
        vulns = c.get("vulnerabilities", [])
        vuln_count += len(vulns)
        for v in vulns:
            if v["severity"] == "CRITICAL": critical_count += 1
            elif v["severity"] == "HIGH":   high_count += 1

        c_risk = prioritize_risk(c, vulns).get("risk_score", 0)
        c["risk_score"] = c_risk
        total_risk = max(total_risk, c_risk)

    return {
        "status": "SIMULATION",
        "upgraded_package": upgrade_name,
        "target_version": target_version,
        "projected_total_risk": total_risk,
        "projected_vulnerability_count": vuln_count,
        "projected_critical_count": critical_count,
        "projected_high_count": high_count,
    }
