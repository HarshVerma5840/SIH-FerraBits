"""
Policy Engine — Security Policy Evaluation
Responsibility: Evaluate structured security findings and risk assessments
against organisation-defined policy rules. Produce PASS / REVIEW / BLOCK decisions.

Boundary rules:
- Does NOT generate vulnerability data.
- Does NOT perform ML inference.
- Does NOT generate SBOM documents.
- Consumes pre-computed findings from security_engine and risk scores from risk_engine.
- Policy decisions are the INPUT to automation_engine (CI/CD gate), not the output.
"""
from typing import Optional

# Default policies applied when no rules are loaded from the database
DEFAULT_POLICY_RULES: list[dict] = [
    {"rule_type": "CVSS_THRESHOLD",   "condition": ">= 9.0", "action": "BLOCK"},
    {"rule_type": "CVSS_THRESHOLD",   "condition": ">= 7.0", "action": "REVIEW"},
    {"rule_type": "ML_ANOMALY",       "condition": ">= 80",  "action": "REVIEW"},
    {"rule_type": "FORBIDDEN_LICENSE","condition": "FORBIDDEN", "action": "BLOCK"},
    {"rule_type": "UNKNOWN_VERSION",  "condition": "UNKNOWN",   "action": "REVIEW"},
]


def evaluate_policy(
    component: dict,
    vulnerabilities: list[dict],
    risk_score: float,
    policy_rules: Optional[list[dict]] = None,
) -> dict:
    """
    Engine 48 / 54: Policy Evaluation Engine.

    Evaluates a single component against all active policy rules and returns
    the most severe applicable action.

    Args:
        component      : Component dict (needs 'version', 'anomaly_score', 'license_classification')
        vulnerabilities: List of CVE findings from security_engine
        risk_score     : Final risk score from risk_engine (0–100)
        policy_rules   : List of policy rule dicts from the database.
                         Falls back to DEFAULT_POLICY_RULES if None or empty.

    Returns:
        action  : 'PASS' | 'REVIEW' | 'BLOCK'
        reasons : list[str] — which rules triggered and why
    """
    rules = policy_rules if policy_rules else DEFAULT_POLICY_RULES

    action = "PASS"
    reasons: list[str] = []

    # ── Rule 1: CVSS threshold ────────────────────────────────────────────────
    if vulnerabilities:
        cvss_scores = [v["cvss_score"] for v in vulnerabilities if v.get("cvss_score")]
        max_cvss = max(cvss_scores) if cvss_scores else 0.0

        for rule in rules:
            if rule["rule_type"] == "CVSS_THRESHOLD":
                threshold = _parse_threshold(rule["condition"])
                if threshold is not None and max_cvss >= threshold:
                    rule_act = rule["action"]
                    reasons.append(
                        f"Vulnerability CVSS score {max_cvss} triggers "
                        f"{rule_act} rule ({rule['condition']})"
                    )
                    action = _escalate(action, rule_act)

    # ── Rule 2: ML anomaly threshold ─────────────────────────────────────────
    ml_score = component.get("anomaly_score", 0)
    for rule in rules:
        if rule["rule_type"] in ("ML_ANOMALY", "AI_ANOMALY"):
            threshold = _parse_threshold(rule["condition"])
            if threshold is not None and ml_score >= threshold:
                rule_act = rule["action"]
                reasons.append(
                    f"ML Anomaly score {ml_score} triggers "
                    f"{rule_act} rule ({rule['condition']})"
                )
                action = _escalate(action, rule_act)

    # ── Rule 3: Forbidden license ─────────────────────────────────────────────
    license_class = component.get("license_classification", "PERMISSIVE")
    for rule in rules:
        if rule["rule_type"] == "FORBIDDEN_LICENSE":
            if rule["condition"] == "FORBIDDEN" and license_class == "FORBIDDEN":
                rule_act = rule["action"]
                reasons.append(f"Forbidden copyleft license triggers {rule_act}")
                action = _escalate(action, rule_act)

    # ── Rule 4: Unknown version ───────────────────────────────────────────────
    version = component.get("version", "UNKNOWN")
    for rule in rules:
        if rule["rule_type"] == "UNKNOWN_VERSION":
            if version in ("UNKNOWN", "unknown"):
                rule_act = rule["action"]
                reasons.append(f"Unknown component version triggers {rule_act}")
                action = _escalate(action, rule_act)

    return {"action": action, "reasons": reasons}


# ── Internal helpers ──────────────────────────────────────────────────────────

_ACTION_PRIORITY = {"PASS": 0, "REVIEW": 1, "BLOCK": 2}


def _escalate(current: str, new: str) -> str:
    """Return the more severe of two policy actions."""
    return new if _ACTION_PRIORITY.get(new, 0) > _ACTION_PRIORITY.get(current, 0) else current


def _parse_threshold(condition: str) -> Optional[float]:
    """Parse '>= 9.0' style condition strings. Returns float or None."""
    condition = condition.strip()
    for op in (">=", "<=", ">", "<", "=="):
        if condition.startswith(op):
            try:
                return float(condition[len(op):].strip())
            except ValueError:
                return None
    return None
