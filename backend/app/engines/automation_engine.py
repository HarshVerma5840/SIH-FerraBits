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

def evaluate_policy(component, vulnerabilities, policy_rules):
    """
    Engine 48: Policy Evaluation Engine
    Engine 54: Policy-as-Code Engine
    Evaluates components against stored policies.
    """
    # Default policy rules if none exist in the database
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
    
    # Aggregate action: BLOCK > REVIEW > PASS
    actions = [cvss_action, anomaly_action, license_action, version_action]
    if "BLOCK" in actions:
        action = "BLOCK"
    elif "REVIEW" in actions:
        action = "REVIEW"
    else:
        action = "PASS"
        
    return {
        "action": action,
        "reasons": reasons
    }

def run_cicd_gate(components_with_evals):
    """
    Engine 49: CI/CD Security Gate Engine
    Evaluates global result based on component actions.
    Returns:
        PASS (exit code 0)
        REVIEW (exit code 1)
        BLOCK (exit code 2)
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
        "reviewed_components_count": review_count
    }

def format_developer_feedback(components_with_evals, gate_result):
    """Engine 53: Automated Developer Feedback Engine"""
    lines = []
    lines.append("====================================================")
    lines.append(" SBOMGUARD CI/CD GATE SECURITY ANALYSIS REPORT")
    lines.append(f" STATUS: {gate_result['status']} (Exit Code: {gate_result['exit_code']})")
    lines.append("====================================================")
    
    violations = [c for c in components_with_evals if c.get("policy_action") in ["BLOCK", "REVIEW"]]
    if not violations:
        lines.append("\n[PASS] All packages conform to security policies. No violations found.")
    else:
        lines.append(f"\n[!] Flagged {len(violations)} package violations:")
        for idx, v in enumerate(violations):
            lines.append(f"  {idx+1}. [{v['policy_action']}] {v['name']}@{v.get('version')} ({v['ecosystem']})")
            for r in v.get("policy_reasons", []):
                lines.append(f"     - {r}")
                
    lines.append("\nRemediation Recommendations:")
    for v in violations:
        rec = v.get("remediation_recommendation", {})
        if rec and rec.get("remediation_recommended"):
            lines.append(f"  - {v['name']}: {rec.get('explanation')}")
            
    lines.append("\n====================================================")
    return "\n".join(lines)
