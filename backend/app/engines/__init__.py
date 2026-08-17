# Expose core engines for pipeline imports
from .discovery_engine import run_repository_discovery, detect_languages, discover_manifests
from .sbom_engine import (
    generate_purl, generate_cyclonedx, generate_spdx, 
    normalize_sbom, validate_sbom, calculate_quality_score, 
    generate_evidence, detect_drift, sign_sbom, verify_sbom_signature
)
from .security_engine import (
    run_vulnerability_detection, detect_dependency_confusion, 
    detect_supply_chain_attack, detect_lifecycle_status, 
    analyze_package_reputation, verify_cryptographic_integrity, 
    compute_cross_project_intelligence, evaluate_contextual_security,
    OFFLINE_VULN_DB
)
from .graph_engine import build_dependency_graph, calculate_blast_radius
from .license_engine import classify_license
from .ai_engine import (
    run_anomaly_detection, classify_malicious_dependency, 
    prioritize_risk, analyze_supply_chain_behavior, 
    generate_security_explanation, get_remediation_recommendation, 
    run_whatif_simulation
)
from .automation_engine import evaluate_policy, run_cicd_gate, format_developer_feedback
from .governance_engine import check_permission, check_risk_acceptance, generate_csv_report, generate_executive_json_report
