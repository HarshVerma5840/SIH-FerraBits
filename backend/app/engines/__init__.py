"""
SBOMGuard AI — Engine Package Exports
All public symbols re-exported here so scan_pipeline.py and API routes
require zero import changes after the architectural refactor.
"""

# ── Discovery ─────────────────────────────────────────────────────────────────
from backend.app.engines.discovery_engine import (
    detect_languages,
    detect_ecosystems,
    discover_manifests,
    parse_package_json,
    parse_package_lock,
    parse_requirements_txt,
    parse_pom_xml,
    parse_dockerfile,
    discover_dependencies,
    run_repository_discovery,
)

# ── SBOM Generation & Verification ───────────────────────────────────────────
from backend.app.engines.sbom_engine import (
    generate_purl,
    generate_cyclonedx,
    generate_spdx,
    normalize_sbom,
    validate_sbom,
    calculate_quality_score,
    generate_evidence,
    detect_drift,
    sign_sbom,
    verify_sbom_signature,
)

# ── Security Analysis (deterministic) ────────────────────────────────────────
from backend.app.engines.security_engine import (
    OFFLINE_VULN_DB,
    parse_semver,
    is_version_affected,
    run_vulnerability_detection,
    detect_dependency_confusion,
    detect_supply_chain_attack,
    detect_lifecycle_status,
    analyze_package_reputation,
    verify_cryptographic_integrity,
    compute_cross_project_intelligence,
    evaluate_contextual_security,
)

# ── Security Intelligence Layer (OSV) ────────────────────────────────────────
from backend.app.engines.intelligence_layer import (
    query_osv_vulnerabilities,
    query_osv_with_offline_fallback,
)

# ── Graph Analysis ────────────────────────────────────────────────────────────
from backend.app.engines.graph_engine import (
    build_dependency_graph,
    calculate_blast_radius,
)

# ── License Analysis ──────────────────────────────────────────────────────────
from backend.app.engines.license_engine import (
    classify_license,
)

# ── ML Inference (anomaly detection prototype) ───────────────────────────────
from backend.app.engines.ai_engine import (
    analyze_dependency,
)

# ── Risk Assessment (combines security + graph + ML signals) ─────────────────
from backend.app.engines.risk_engine import (
    prioritize_risk,
    analyze_supply_chain_behavior,
)

# ── Explanation & Remediation ─────────────────────────────────────────────────
from backend.app.engines.explanation_engine import (
    generate_security_explanation,
    get_remediation_recommendation,
    run_whatif_simulation,
)

# ── Policy Evaluation ─────────────────────────────────────────────────────────
from backend.app.engines.policy_engine import (
    evaluate_policy,
)

# ── Automation & CI/CD Gate ───────────────────────────────────────────────────
from backend.app.engines.automation_engine import (
    run_cicd_gate,
    format_developer_feedback,
)

# ── Governance ────────────────────────────────────────────────────────────────
from backend.app.engines.governance_engine import (
    check_permission,
    check_risk_acceptance,
    generate_csv_report,
    generate_executive_json_report,
)

