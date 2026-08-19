"""
Automation Engine — CI/CD Workflow Execution
Responsibility: Execute workflow actions based on completed policy decisions.
Formats the final gate result and developer-facing feedback report.

Boundary rules:
- Does NOT calculate vulnerability severity.
- Does NOT train or run ML models.
- Does NOT perform CVE matching.
- Consumes policy decisions from policy_engine; does NOT produce them.

Note: evaluate_policy() has been moved to policy_engine.py
"""


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
