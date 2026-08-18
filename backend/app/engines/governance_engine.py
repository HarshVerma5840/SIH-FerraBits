import csv
import io
import json
from datetime import datetime, timezone

# RBAC Permissions Matrix
ROLE_PERMISSIONS = {
    "ADMIN": ["view_dashboard", "run_scan", "edit_policies", "accept_risk", "manage_users", "view_audit_logs", "manage_tickets"],
    "SECURITY_ANALYST": ["view_dashboard", "run_scan", "view_policies", "accept_risk", "view_audit_logs", "manage_tickets"],
    "DEVELOPER": ["view_dashboard", "run_scan", "view_policies", "manage_tickets"],
    "VIEWER": ["view_dashboard"]
}

def check_permission(user_role, required_action):
    """Engine 56: RBAC Engine"""
    role = user_role.upper() if user_role else "VIEWER"
    permissions = ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["VIEWER"])
    return required_action in permissions

def _is_exception_expired(expires):
    try:
        exp_dt = datetime.strptime(expires, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp_dt
    except Exception:
        return False

def check_risk_acceptance(accepted_exceptions, component_purl, cve_id=None):
    """
    Engine 55: Risk Acceptance / Exception Engine
    Checks if a vulnerability or component has a valid accepted exception.
    """
    for exp in accepted_exceptions:
        if exp.get("component_purl") != component_purl:
            continue
        cve = exp.get("cve_id")
        if cve and cve != cve_id:
            continue
        expires = exp.get("expires_at")
        if expires and _is_exception_expired(expires):
            continue
        return True, exp.get("reason", "Accepted by security team")
    return False, None

def generate_csv_report(components, vulnerabilities, risk_assessments):
    """Engine 58: Security Reporting Engine (CSV Export)"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Component Name", "Version", "Ecosystem", "PURL", "License", "Risk Score", "Risk Level", "CVE IDs", "CVSS Score"])
    
    # Map assessments and vulns by purl
    assess_map = {r["component_purl"]: r for r in risk_assessments}
    vuln_map = {}
    for v in vulnerabilities:
        purl = v["component_purl"]
        if purl not in vuln_map:
            vuln_map[purl] = []
        vuln_map[purl].append(v)
        
    for c in components:
        purl = c["purl"]
        assess = assess_map.get(purl, {})
        cvs = vuln_map.get(purl, [])
        cve_list = [v["cve_id"] for v in cvs]
        max_cvss = max([v["cvss_score"] for v in cvs if v["cvss_score"]] or [0.0])
        
        writer.writerow([
            c["name"],
            c.get("version", "UNKNOWN"),
            c["ecosystem"],
            purl,
            c.get("license", "Unknown"),
            assess.get("risk_score", 0),
            assess.get("risk_level", "LOW"),
            "; ".join(cve_list) if cve_list else "None",
            max_cvss if cve_list else "N/A"
        ])
        
    return output.getvalue()

def generate_executive_json_report(project, scan, components, vulnerabilities, risk_assessments, quality_info):
    """Engine 58: Security Reporting Engine (Executive Report JSON)"""
    vulns_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulnerabilities:
        sev = v["severity"].upper()
        if sev in vulns_by_severity:
            vulns_by_severity[sev] += 1
            
    risk_by_level = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in risk_assessments:
        lvl = r["risk_level"].upper()
        if lvl in risk_by_level:
            risk_by_level[lvl] += 1
            
    return {
        "report_type": "EXECUTIVE_SECURITY_SUMMARY",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "project": {
            "name": project.name,
            "description": project.description,
        },
        "scan": {
            "id": scan.id,
            "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else None,
            "status": scan.status
        },
        "metrics": {
            "total_components": len(components),
            "vulnerability_summary": vulns_by_severity,
            "risk_assessment_distribution": risk_by_level,
            "sbom_quality_score": quality_info.get("score", 0)
        }
    }
