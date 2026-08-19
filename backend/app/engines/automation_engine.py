"""
Automation Engine — CI/CD Workflow Execution
Responsibility: Execute workflow actions based on completed policy decisions.
Formats the final gate result and developer-facing feedback report.

Boundary rules:
- Does NOT calculate vulnerability severity.
- Does NOT train or run ML models.
- Does NOT perform CVE matching.
- Consumes policy decisions from policy_engine; does NOT produce them.

Note: evaluate_policy() helper is included here for backward-compatibility with
pipeline imports. The canonical home is policy_engine.py.
"""


def _evaluate_cvss(vulnerabilities, policy_rules, reasons):
    if not vulnerabilities:
        return "PASS"
    max_cvss = max([v["cvss_score"] for v in vulnerabilities if v.get("cvss_score")] or [0])
    action = "PASS"
    for rule in policy_rules:
        if rule["rule_type"] != "CVSS_THRESHOLD":
            continue
        cond = rule["condition"]
        rule_act = rule["action"]
        if not cond.startswith(">="):
            continue
        val = float(cond.replace(">=", "").strip())
        if max_cvss < val:
            continue
        reasons.append(f"Vulnerability CVSS score {max_cvss} triggers {rule_act} rule ({cond})")
        if rule_act == "BLOCK":
            action = "BLOCK"
        elif rule_act == "REVIEW" and action != "BLOCK":
            action = "REVIEW"
    return action


def _evaluate_anomaly(component, policy_rules, reasons):
    ai_score = component.get("anomaly_score", 0)
    action = "PASS"
    for rule in policy_rules:
        if rule["rule_type"] != "AI_ANOMALY":
            continue
        cond = rule["condition"]
        rule_act = rule["action"]
        if not cond.startswith(">="):
            continue
        val = float(cond.replace(">=", "").strip())
        if ai_score < val:
            continue
        reasons.append(f"AI Anomaly score {ai_score} triggers {rule_act} rule ({cond})")
        if rule_act == "BLOCK":
            action = "BLOCK"
        elif rule_act == "REVIEW" and action != "BLOCK":
            action = "REVIEW"
    return action


def _evaluate_license(component, policy_rules, reasons):
    action = "PASS"
    license_class = component.get("license_classification", "PERMISSIVE")
    for rule in policy_rules:
        if rule["rule_type"] != "FORBIDDEN_LICENSE":
            continue
        cond = rule["condition"]
        rule_act = rule["action"]
        if cond != "FORBIDDEN" or license_class != "FORBIDDEN":
            continue
        reasons.append(f"Forbidden copyleft license triggers {rule_act}")
        if rule_act == "BLOCK":
            action = "BLOCK"
        elif rule_act == "REVIEW" and action != "BLOCK":
            action = "REVIEW"
    return action


def _evaluate_version(component, policy_rules, reasons):
    action = "PASS"
    version = component.get("version", "UNKNOWN")
    for rule in policy_rules:
        if rule["rule_type"] != "UNKNOWN_VERSION":
            continue
        rule_act = rule["action"]
        if version not in ("UNKNOWN", "unknown"):
            continue
        reasons.append(f"Unknown component version triggers {rule_act}")
        if rule_act == "BLOCK":
            action = "BLOCK"
        elif rule_act == "REVIEW" and action != "BLOCK":
            action = "REVIEW"
    return action


def evaluate_policy(component, vulnerabilities, risk_score_or_rules=None, policy_rules=None):
    """
    Engine 48: Policy Evaluation Engine / Engine 54: Policy-as-Code Engine.
    Evaluates components against stored policies.

    Accepts both the old 3-arg signature (component, vulnerabilities, policy_rules)
    and the new 4-arg signature (component, vulnerabilities, risk_score, policy_rules).
    """
    # Handle both old and new call signatures
    if policy_rules is None:
        # Old 3-arg call: evaluate_policy(comp, vulns, policy_rules)
        if isinstance(risk_score_or_rules, list):
            policy_rules = risk_score_or_rules
        else:
            policy_rules = []
    # else: new 4-arg call, policy_rules already set

    # Default policy rules if none provided
    if not policy_rules:
        policy_rules = [
            {"rule_type": "CVSS_THRESHOLD", "condition": ">= 9.0", "action": "BLOCK"},
            {"rule_type": "CVSS_THRESHOLD", "condition": ">= 7.0", "action": "REVIEW"},
            {"rule_type": "AI_ANOMALY", "condition": ">= 80", "action": "REVIEW"},
            {"rule_type": "FORBIDDEN_LICENSE", "condition": "FORBIDDEN", "action": "BLOCK"},
            {"rule_type": "UNKNOWN_VERSION", "condition": "UNKNOWN", "action": "REVIEW"}
        ]

    reasons = []
    cvss_action = _evaluate_cvss(vulnerabilities, policy_rules, reasons)
    anomaly_action = _evaluate_anomaly(component, policy_rules, reasons)
    license_action = _evaluate_license(component, policy_rules, reasons)
    version_action = _evaluate_version(component, policy_rules, reasons)

    actions = [cvss_action, anomaly_action, license_action, version_action]
    if "BLOCK" in actions:
        action = "BLOCK"
    elif "REVIEW" in actions:
        action = "REVIEW"
    else:
        action = "PASS"

    return {"action": action, "reasons": reasons}


def run_cicd_gate(components_with_evals: list[dict]) -> dict:
    """
    Engine 49: CI/CD Security Gate Engine.

    Reads the 'policy_action' field on each component (set by policy_engine)
    and produces the final global gate decision.

    Exit codes:
        0 = PASS
        1 = REVIEW
        2 = BLOCK

    Args:
        components_with_evals: Component dicts that include 'policy_action' field.

    Returns:
        status                   : 'PASS' | 'REVIEW' | 'BLOCK'
        exit_code                : int
        blocked_components_count : int
        reviewed_components_count: int
    """
    global_action = "PASS"
    exit_code = 0
    blocked_count = 0
    review_count = 0

    for comp in components_with_evals:
        act = comp.get("policy_action", "PASS")
        if act == "BLOCK":
            blocked_count += 1
        elif act == "REVIEW":
            review_count += 1

    if blocked_count > 0:
        global_action = "BLOCK"
        exit_code = 2
    elif review_count > 0:
        global_action = "REVIEW"
        exit_code = 1

    return {
        "status": global_action,
        "exit_code": exit_code,
        "blocked_components_count": blocked_count,
        "reviewed_components_count": review_count,
    }


def format_developer_feedback(
    components_with_evals: list[dict],
    gate_result: dict,
) -> str:
    """
    Engine 53: Automated Developer Feedback Engine.

    Formats a structured plain-text security gate report for developer consumption.
    Relies on 'policy_action', 'policy_reasons', and 'remediation_recommendation'
    fields set earlier in the pipeline.

    Args:
        components_with_evals: Fully evaluated component list.
        gate_result          : Output from run_cicd_gate().

    Returns:
        str — formatted CI/CD gate report
    """
    lines = [
        "====================================================",
        " SBOMGUARD CI/CD GATE SECURITY ANALYSIS REPORT",
        f" STATUS: {gate_result['status']} (Exit Code: {gate_result['exit_code']})",
        "====================================================",
    ]

    violations = [
        c for c in components_with_evals
        if c.get("policy_action") in ("BLOCK", "REVIEW")
    ]

    if not violations:
        lines.append("\n[PASS] All packages conform to security policies. No violations found.")
    else:
        lines.append(f"\n[!] Flagged {len(violations)} package violations:")
        for idx, v in enumerate(violations):
            lines.append(
                f"  {idx+1}. [{v['policy_action']}] "
                f"{v['name']}@{v.get('version')} ({v['ecosystem']})"
            )
            for r in v.get("policy_reasons", []):
                lines.append(f"     - {r}")

    lines.append("\nRemediation Recommendations:")
    for v in violations:
        rec = v.get("remediation_recommendation", {})
        if rec and rec.get("remediation_recommended"):
            lines.append(f"  - {v['name']}: {rec.get('explanation')}")

    lines.append("\n====================================================")
    return "\n".join(lines)
