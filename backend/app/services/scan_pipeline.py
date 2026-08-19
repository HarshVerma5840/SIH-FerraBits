import os
import json
import uuid
import hashlib
import traceback
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.models.database import (
    Scan, Project, SBOM, SBOMComponent, Dependency, Vulnerability,
    Anomaly, RiskAssessment, Ticket, Alert, AuditLog, SBOMVersion,
    SBOMDiff, Evidence, RemediationRecommendation, MLPrediction, Policy
)
from backend.app.engines import (
    run_repository_discovery, generate_purl, generate_cyclonedx,
    normalize_sbom, validate_sbom, calculate_quality_score,
    generate_evidence, detect_drift, sign_sbom, verify_sbom_signature,
    run_vulnerability_detection, detect_dependency_confusion,
    detect_supply_chain_attack, detect_lifecycle_status,
    analyze_package_reputation, verify_cryptographic_integrity,
    compute_cross_project_intelligence, evaluate_contextual_security,
    build_dependency_graph, calculate_blast_radius, classify_license,
    run_anomaly_detection, classify_malicious_dependency,
    prioritize_risk, analyze_supply_chain_behavior,
    generate_security_explanation, get_remediation_recommendation,
    evaluate_policy, run_cicd_gate, format_developer_feedback
)

def _log_msg(msg, logs):
    print(msg)
    logs.append(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")

def _run_discovery_phase(target_dir, logs):
    _log_msg("Running Repository Discovery, Language & Ecosystem detection...", logs)
    discovery_results = run_repository_discovery(target_dir)
    
    langs_found = ", ".join(discovery_results["languages"])
    ecos_found = ", ".join(discovery_results["ecosystems"])
    _log_msg(f"Languages detected: {langs_found or 'None'}", logs)
    _log_msg(f"Ecosystems detected: {ecos_found or 'None'}", logs)
    _log_msg(f"Discovered {len(discovery_results['manifests'])} manifest files.", logs)
    _log_msg(f"Found {len(discovery_results['components'])} unique dependencies.", logs)
    return discovery_results

def _profile_single_component(comp_data, scan, existing_vulns, db):
    name = comp_data["name"]
    version = comp_data.get("version", "UNKNOWN")
    eco = comp_data["ecosystem"]
    
    # PURL Generation (Engine 10)
    purl = generate_purl(eco, name, version)
    comp_data["purl"] = purl
    
    # Code Evidence & Provenance (Engine 15)
    evidence_data = generate_evidence(comp_data)
    comp_data["confidence"] = evidence_data["confidence_score"]
    
    # Cryptographic Integrity Check (Engine 28)
    _ = verify_cryptographic_integrity(comp_data)
    
    # License Classification (Engine 25)
    license_name = comp_data.get("license", "Unknown")
    spdx_lic, lic_action, _ = classify_license(license_name)
    comp_data["license"] = spdx_lic
    comp_data["license_classification"] = lic_action
    
    # Create Component Record
    comp_model = SBOMComponent(
        name=name,
        version=version,
        ecosystem=eco,
        purl=purl,
        supplier=comp_data.get("supplier", "Unknown"),
        repository=comp_data.get("repository", "Unknown"),
        license=spdx_lic,
        hash_sha256=comp_data.get("hash", "Unknown"),
        component_type=comp_data.get("type", "library"),
        depth=comp_data.get("depth", 0),
        direct=comp_data.get("direct", True),
        source_file=comp_data.get("source_file"),
        confidence=comp_data["confidence"]
    )
    
    # Add Evidence Record (Engine 15)
    evidence_rec = Evidence(
        filepath=evidence_data["filepath"],
        evidence_type=evidence_data["evidence_type"],
        confidence_score=evidence_data["confidence_score"]
    )
    comp_model.evidence.append(evidence_rec)
    
    # Run ML Anomaly Detection (Engine 35)
    anomaly_res = run_anomaly_detection(comp_data)
    comp_data["anomaly_score"] = anomaly_res["anomaly_score"]
    
    # Save ML predictions into MLPrediction table
    ml_pred_anomaly = MLPrediction(
        component_purl=purl,
        prediction_type="anomaly",
        features_json=json.dumps(anomaly_res.get("indicators", [])),
        prediction_output_json=json.dumps(anomaly_res),
        confidence_score=anomaly_res["anomaly_probability"]
    )
    scan.ml_predictions.append(ml_pred_anomaly)
    
    # Add Anomaly Record
    anomaly_rec = Anomaly(
        component_purl=purl,
        anomaly_score=anomaly_res["anomaly_score"],
        anomaly_probability=anomaly_res["anomaly_probability"],
        classification=anomaly_res["classification"],
        indicators_json=json.dumps(anomaly_res["indicators"])
    )
    scan.anomalies.append(anomaly_rec)
    
    # Run ML Malicious Classification (Engine 36 / 22)
    malicious_res = classify_malicious_dependency(comp_data)
    ml_pred_malicious = MLPrediction(
        component_purl=purl,
        prediction_type="malicious_classifier",
        features_json=json.dumps(malicious_res.get("contributing_features", [])),
        prediction_output_json=json.dumps(malicious_res),
        confidence_score=malicious_res["probability"]
    )
    scan.ml_predictions.append(ml_pred_malicious)
    
    # Run Dependency Confusion checks (Engine 23)
    _ = detect_dependency_confusion(comp_data)
    
    # Run Supply Chain Attack detection (Engine 24)
    _ = detect_supply_chain_attack(comp_data)
    
    # Run Lifecycle checks (Engine 26)
    _ = detect_lifecycle_status(comp_data)
    
    # Run Reputation analysis (Engine 27)
    _ = analyze_package_reputation(comp_data)
    
    # Run Vulnerability Matching (Engine 19 / 20)
    vuln_matches = run_vulnerability_detection([comp_data])
    comp_vulns = []
    for v_match in vuln_matches:
        cve = v_match["cve_id"]
        vuln_db = existing_vulns.get(cve)
        if not vuln_db:
            vuln_db = Vulnerability(
                cve_id=cve,
                cvss_score=v_match["cvss_score"],
                severity=v_match["severity"],
                affected_versions=v_match["affected_versions"],
                fixed_versions=v_match["fixed_versions"],
                description=v_match["description"],
                references_json=v_match["references_json"]
            )
            db.add(vuln_db)
            existing_vulns[cve] = vuln_db
        comp_model.vulnerabilities.append(vuln_db)
        c_vuln = {
            "cve_id": vuln_db.cve_id,
            "cvss_score": vuln_db.cvss_score,
            "severity": vuln_db.severity,
            "affected_versions": vuln_db.affected_versions,
            "fixed_versions": vuln_db.fixed_versions,
            "description": vuln_db.description
        }
        comp_vulns.append(c_vuln)
        
    return comp_model, comp_vulns, purl

def _evaluate_comp_policy_and_tickets(project_id, scan, project, comp_data, comp_vulns, risk_res, risk_desc, remediation_res, policy_rules, logs):
    purl = comp_data["purl"]
    version = comp_data.get("version", "UNKNOWN")
    policy_eval_res = evaluate_policy(comp_data, comp_vulns, policy_rules)
    comp_data["policy_action"] = policy_eval_res["action"]
    comp_data["policy_reasons"] = policy_eval_res["reasons"]
    comp_data["remediation_recommendation"] = remediation_res
    
    if policy_eval_res["action"] in ["BLOCK", "REVIEW"]:
        alert_rec = Alert(
            project_id=project_id,
            component_purl=purl,
            risk_score=risk_res["risk_score"],
            reason="; ".join(policy_eval_res["reasons"]),
            policy_action=policy_eval_res["action"],
            is_resolved=False
        )
        scan.alerts.append(alert_rec)
        
        if risk_res["risk_level"] in ["CRITICAL", "HIGH"]:
            ticket_id = f"SEC-{uuid.uuid4().hex[:6].upper()}"
            ticket_rec = Ticket(
                ticket_id=ticket_id,
                project_id=project_id,
                component_name=comp_data["name"],
                component_version=version,
                severity=risk_res["risk_level"],
                risk_score=risk_res["risk_score"],
                description=f"Automated policy violation ticket: {risk_desc}",
                recommendation=remediation_res.get("explanation", "Upgrade package"),
                status="OPEN"
            )
            project.tickets.append(ticket_rec)
            _log_msg(f"Auto-created ticket {ticket_id} for package '{comp_data['name']}' due to {risk_res['risk_level']} risk level.", logs)

def _parse_dependencies(discovery_results):
    relations = {}
    for comp in discovery_results["components"]:
        purl = comp["purl"]
        if comp.get("dependencies"):
            children_purls = []
            for child_name in comp["dependencies"]:
                child_match = next((c for c in discovery_results["components"] if c["name"] == child_name and c["ecosystem"] == comp["ecosystem"]), None)
                if child_match:
                    children_purls.append(child_match["purl"])
            if children_purls:
                relations[purl] = children_purls
    return relations

def _evaluate_single_component_risk(project_id, scan, project, comp_data, graph_data, purl_to_vulns, policy_rules, logs):
    purl = comp_data["purl"]
    
    # Blast Radius (Engine 31)
    blast_radius_res = calculate_blast_radius(purl, graph_data["nodes"], graph_data["edges"])
    
    # Contextual Security & VEX (Engine 33 / 34)
    comp_vulns = purl_to_vulns[purl]
    _ = evaluate_contextual_security(comp_data, comp_vulns)
    
    # Risk Prioritization (Engine 37)
    anomaly_info = {"anomaly_score": comp_data["anomaly_score"]}
    risk_res = prioritize_risk(comp_data, comp_vulns, blast_radius_res, anomaly_info)
    comp_data["risk_score"] = risk_res["risk_score"]
    
    risk_desc = generate_security_explanation(comp_data, comp_vulns, risk_res["risk_score"], blast_radius_res)
    risk_model = RiskAssessment(
        component_purl=purl,
        risk_score=risk_res["risk_score"],
        risk_level=risk_res["risk_level"],
        explanation=risk_desc,
        blast_radius_json=json.dumps(blast_radius_res),
        production_exposure=blast_radius_res["production_exposure"]
    )
    scan.risk_assessments.append(risk_model)
    
    remediation_res = get_remediation_recommendation(comp_data, comp_vulns)
    if remediation_res["remediation_recommended"]:
        rem_model = RemediationRecommendation(
            component_purl=purl,
            current_version=remediation_res["current_version"],
            recommended_version=remediation_res["recommended_version"],
            upgrade_impact=remediation_res["upgrade_impact"],
            remediation_type="upgrade"
        )
        scan.remediations.append(rem_model)
        
    _evaluate_comp_policy_and_tickets(
        project_id, scan, project, comp_data, comp_vulns, risk_res, risk_desc, remediation_res, policy_rules, logs
    )

def _run_graph_and_risk_phase(project_id, scan, project, components_for_graph, purl_to_vulns, discovery_results, policy_rules, logs):
    _log_msg("Building Dependency Attack Graph...", logs)
    relations = _parse_dependencies(discovery_results)
                
    graph_data = build_dependency_graph(components_for_graph, relations)
    pending_dependencies = []
    for edge in graph_data["edges"]:
        pending_dependencies.append((edge["target"], edge["source"]))
        
    _log_msg("Calculating Blast Radius, VEX Context, and Risk scores...", logs)
    for comp_data in components_for_graph:
        _evaluate_single_component_risk(project_id, scan, project, comp_data, graph_data, purl_to_vulns, policy_rules, logs)
        
    return graph_data, pending_dependencies

def _run_sbom_compilation_phase(project_id, scan_id, project, components_for_graph, processed_components, graph_data, pending_dependencies, logs, db):
    _log_msg("Compiling SBOM documents...", logs)
    cdx_relations = {}
    for edge in graph_data["edges"]:
        s = edge["source"]
        t = edge["target"]
        if s not in cdx_relations:
            cdx_relations[s] = []
        cdx_relations[s].append(t)
        
    cyclonedx_sbom = generate_cyclonedx(project.name, components_for_graph, cdx_relations)
    raw_json_str = json.dumps(cyclonedx_sbom, indent=2)
    
    file_hash = hashlib.sha256(raw_json_str.encode("utf-8")).hexdigest()
    signature_str = sign_sbom(cyclonedx_sbom)
    verification_status = verify_sbom_signature(cyclonedx_sbom, signature_str)
    
    is_valid, validation_errors = validate_sbom(cyclonedx_sbom)
    if not is_valid:
        _log_msg(f"SBOM Validation WARNING: {validation_errors}", logs)
        
    sbom_model = SBOM(
        scan_id=scan_id,
        project_id=project_id,
        format="CycloneDX",
        version="1.4",
        raw_json=raw_json_str,
        file_hash=file_hash,
        signature=signature_str,
        verification_status=verification_status
    )
    
    for c_model in processed_components:
        sbom_model.components.append(c_model)
        
    db.add(sbom_model)
    db.commit()
    db.refresh(sbom_model)
    
    for target, source in pending_dependencies:
        dep_rel = Dependency(
            sbom_id=sbom_model.id,
            component_purl=target,
            dependent_purl=source
        )
        db.add(dep_rel)
    db.commit()
    
    quality_score_res = calculate_quality_score(components_for_graph)
    _log_msg(f"SBOM Quality score calculated: {quality_score_res['score']}/100", logs)
    
    return sbom_model, cyclonedx_sbom, quality_score_res

def _run_post_scan_phase(project_id, scan, project, sbom_model, cyclonedx_sbom, quality_score_res, components_for_graph, logs, db):
    gate_res = run_cicd_gate(components_for_graph)
    _ = format_developer_feedback(components_for_graph, gate_res)
    
    prev_version = db.query(SBOMVersion).filter_by(project_id=project_id).order_by(SBOMVersion.version_number.desc()).first()
    new_version_num = 1 if not prev_version else prev_version.version_number + 1
    
    sbom_ver = SBOMVersion(
        project_id=project_id,
        version_number=new_version_num,
        sbom_id=sbom_model.id
    )
    db.add(sbom_ver)
    
    if prev_version:
        _log_msg("Comparing SBOM with previous version to calculate diffs...", logs)
        prev_sbom = db.query(SBOM).get(prev_version.sbom_id)
        prev_normalized = normalize_sbom(json.loads(prev_sbom.raw_json))
        curr_normalized = normalize_sbom(cyclonedx_sbom)
        
        prev_map = {c["purl"]: c for c in prev_normalized}
        curr_map = {c["purl"]: c for c in curr_normalized}
        
        added = [c for c in curr_normalized if c["purl"] not in prev_map]
        removed = [c for c in prev_normalized if c["purl"] not in curr_map]
        
        updated = []
        for purl, c in curr_map.items():
            if purl in prev_map:
                prev_c = prev_map[purl]
                if c["version"] != prev_c["version"] or c["license"] != prev_c["license"]:
                    updated.append({
                        "name": c["name"],
                        "old_version": prev_c["version"],
                        "new_version": c["version"],
                        "old_license": prev_c["license"],
                        "new_license": c["license"]
                    })
                    
        diff_model = SBOMDiff(
            project_id=project_id,
            base_scan_id=prev_version.sbom_id,
            head_scan_id=sbom_model.id,
            added_json=json.dumps(added),
            removed_json=json.dumps(removed),
            updated_json=json.dumps(updated)
        )
        db.add(diff_model)
        
    db.commit()
    
    audit_rec = AuditLog(
        username=scan.triggered_by,
        action="scan_completed",
        details=f"Completed security scan for project '{project.name}' (Quality: {quality_score_res['score']}, Gate: {gate_res['status']})",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    
    _log_msg(f"Scan complete. Gate decision: {gate_res['status']}.", logs)
    scan.status = "COMPLETED"
    scan.completed_at = datetime.now(timezone.utc)
    scan.log = "\n".join(logs)
    db.commit()

def run_scan_pipeline(project_id: int, scan_id: int, target_dir: str, db: Session):
    """
    Orchestrates the entire scanning lifecycle, triggering all 58 engines.
    """
    scan = db.query(Scan).get(scan_id)
    project = db.query(Project).get(project_id)
    
    if not scan or not project:
        return
        
    scan.status = "RUNNING"
    scan.started_at = datetime.now(timezone.utc)
    db.commit()
    
    logs = []
    try:
        _log_msg(f"Starting scan {scan_id} for project '{project.name}' in directory: {target_dir}", logs)
        
        # 1. RUN DISCOVERY PHASE
        discovery_results = _run_discovery_phase(target_dir, logs)
        
        db_policies = db.query(Policy).filter(Policy.is_active == True).all()
        policy_rules = [
            {"rule_type": p.rule_type, "condition": p.rule_condition, "action": p.action}
            for p in db_policies
        ]
        
        # 2. RUN SECURITY & ML ANALYSIS
        existing_vulns = {v.cve_id: v for v in db.query(Vulnerability).all()}
        processed_components = []
        components_for_graph = []
        purl_to_comp_obj = {}
        purl_to_vulns = {}
        
        _log_msg("Starting individual component inspection, ML predictions and vulnerability matching...", logs)
        for comp_data in discovery_results["components"]:
            comp_model, comp_vulns, purl = _profile_single_component(comp_data, scan, existing_vulns, db)
            purl_to_vulns[purl] = comp_vulns
            purl_to_comp_obj[purl] = comp_model
            processed_components.append(comp_model)
            
            graph_node_data = dict(comp_data)
            graph_node_data["vulnerabilities"] = comp_vulns
            components_for_graph.append(graph_node_data)
            
        _log_msg(f"Component security profiling complete. Map contains {len(processed_components)} entries.", logs)
        
        # 3. BUILD ATTACK GRAPH & BLAST RADIUS
        graph_data, pending_dependencies = _run_graph_and_risk_phase(
            project_id, scan, project, components_for_graph, purl_to_vulns, discovery_results, policy_rules, logs
        )
        
        # 4. SBOM COMPILING, SIGNING & VALIDATION
        sbom_model, cyclonedx_sbom, quality_score_res = _run_sbom_compilation_phase(
            project_id, scan_id, project, components_for_graph, processed_components, graph_data, pending_dependencies, logs, db
        )
        
        # 5. POST SCAN PHASE (GATES, HISTORY, DIFF, COMPLETED STATUS)
        _run_post_scan_phase(
            project_id, scan, project, sbom_model, cyclonedx_sbom, quality_score_res, components_for_graph, logs, db
        )
        
    except Exception as e:
        err_msg = traceback.format_exc()
        _log_msg(f"Pipeline error: {str(e)}\n{err_msg}", logs)
        scan.status = "FAILED"
        scan.completed_at = datetime.now(timezone.utc)
        scan.log = "\n".join(logs)
        db.commit()
        
        audit_rec = AuditLog(
            username=scan.triggered_by,
            action="scan_failed",
            details=f"Failed scan {scan_id} for project '{project.name}': {str(e)}",
            ip_address="127.0.0.1"
        )
        db.add(audit_rec)
        db.commit()
