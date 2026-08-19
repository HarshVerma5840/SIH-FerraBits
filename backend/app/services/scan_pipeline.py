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
    SBOMDiff, Evidence, RemediationRecommendation, MLPrediction, Policy,
    SecurityFinding
)
from backend.app.engines import (
    run_repository_discovery, generate_purl, generate_cyclonedx,
    normalize_sbom, validate_sbom, calculate_quality_score,
    generate_evidence, detect_drift, sign_sbom, verify_sbom_signature,
    run_vulnerability_detection, detect_dependency_confusion,
    detect_supply_chain_attack, detect_lifecycle_status,
    analyze_package_reputation, verify_cryptographic_integrity,
    compute_cross_project_intelligence, evaluate_contextual_security,
    query_osv_vulnerabilities, query_osv_with_offline_fallback,
    build_dependency_graph, calculate_blast_radius, classify_license,
    analyze_dependency,
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
    
    # Run Prototype Anomaly Detection (Engine 35)
    anomaly_res = analyze_dependency(comp_data)
    comp_data["anomaly_score"] = anomaly_res["anomaly_score"]
    
    # Save ML predictions into MLPrediction table
    ml_pred_anomaly = MLPrediction(
        component_purl=purl,
        prediction_type="anomaly_prototype",
        features_json=json.dumps(anomaly_res.get("signals", [])),
        prediction_output_json=json.dumps(anomaly_res),
        confidence_score=1.0 # Deterministic prototype
    )
    scan.ml_predictions.append(ml_pred_anomaly)
    
    # Add Anomaly Record
    anomaly_rec = Anomaly(
        component_purl=purl,
        anomaly_score=anomaly_res["anomaly_score"],
        anomaly_probability=1.0,
        classification=anomaly_res["classification"],
        indicators_json=json.dumps(anomaly_res["signals"])
    )
    scan.anomalies.append(anomaly_rec)
    
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

def _run_graph_and_risk_phase(project_id, scan, project, components_for_graph, purl_to_vulns, discovery_results, policy_rules, logs):
    _log_msg("Building Dependency Attack Graph...", logs)
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
                
    graph_data = build_dependency_graph(components_for_graph, relations)
    pending_dependencies = []
    for edge in graph_data["edges"]:
        pending_dependencies.append((edge["target"], edge["source"]))
        
    _log_msg("Calculating Blast Radius, VEX Context, and Risk scores...", logs)
    for comp_data in components_for_graph:
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
    def log(msg):
        print(msg)
        logs.append(f"[{datetime.utcnow().isoformat()}] {msg}")
        
    def update_progress(stage_id: str, message: str, progress: int, stage_status: str = "RUNNING"):
        scan.current_stage = stage_id
        scan.stage_message = message
        scan.overall_progress = progress
        scan.stage_status = stage_status
        db.commit()
        log(message)
        
    try:
        update_progress("INITIALIZING", f"Starting scan {scan_id} for project '{project.name}'", 5)
        
        # 1. RUN DISCOVERY PIPELINE (Engines 1-9)
        update_progress("DISCOVERY", "Running Repository Discovery, Language & Ecosystem detection...", 10)
        discovery_results = run_repository_discovery(target_dir)
        
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
        
        # 2. RUN SECURITY & ML ANALYSIS PER COMPONENT (Engines 10, 15, 16, 22-28, 35-36)
        update_progress("VERSION_RESOLUTION", "Starting individual component inspection and version resolution...", 30)
        for comp_data in discovery_results["components"]:
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
            integrity_status = verify_cryptographic_integrity(comp_data)
            
            # License Classification (Engine 25)
            license_name = comp_data.get("license", "Unknown")
            spdx_lic, lic_action, lic_desc = classify_license(license_name)
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
                version_source=comp_data.get("version_source", "UNKNOWN"),
                version_confidence="HIGH" if comp_data.get("version_source") == "lockfile" else ("MEDIUM" if comp_data.get("version_source") == "manifest" else "UNKNOWN"),
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
            
            # Run Prototype Anomaly Detection (Engine 35)
            anomaly_res = analyze_dependency(comp_data)
            comp_data["anomaly_score"] = anomaly_res["anomaly_score"]
            
            # Save ML predictions into MLPrediction table
            ml_pred_anomaly = MLPrediction(
                component_purl=purl,
                prediction_type="anomaly_prototype",
                features_json=json.dumps(anomaly_res.get("signals", [])),
                prediction_output_json=json.dumps(anomaly_res),
                confidence_score=1.0
            )
            scan.ml_predictions.append(ml_pred_anomaly)
            
            # Add Anomaly Record
            anomaly_rec = Anomaly(
                component_purl=purl,
                anomaly_score=anomaly_res["anomaly_score"],
                anomaly_probability=1.0,
                classification=anomaly_res["classification"],
                indicators_json=json.dumps(anomaly_res["signals"])
            )
            scan.anomalies.append(anomaly_rec)
            
            # Run Dependency Confusion checks (Engine 23)
            confusion_res = detect_dependency_confusion(comp_data)
            
            # Run Supply Chain Attack detection (Engine 24)
            attack_res = detect_supply_chain_attack(comp_data)
            
            # Run Lifecycle checks (Engine 26)
            lifecycle_res = detect_lifecycle_status(comp_data)
            
            # Run Reputation analysis (Engine 27)
            reputation_res = analyze_package_reputation(comp_data)
            
            # ── OSV Vulnerability Intelligence (with offline fallback) ──
            from backend.app.engines.security_engine import OFFLINE_VULN_DB
            vuln_matches, vuln_source = query_osv_with_offline_fallback(
                purl, name, version, eco, OFFLINE_VULN_DB
            )
            comp_vulns = []
            for v_match in vuln_matches:
                # Find or create vulnerability in global database
                vuln_db = db.query(Vulnerability).filter_by(vulnerability_id=v_match["vulnerability_id"]).first()
                if not vuln_db:
                    vuln_db = Vulnerability(
                        vulnerability_id=v_match["vulnerability_id"],
                        aliases=v_match["aliases"],
                        summary=v_match["summary"],
                        cvss_score=v_match["cvss_score"],
                        severity_level=v_match["severity_level"],
                        affected_versions=v_match["affected_versions"],
                        fixed_versions=v_match["fixed_versions"],
                        known_exploited=v_match["known_exploited"],
                        source=v_match["source"],
                        source_url=v_match["source_url"],
                        retrieved_at=datetime.fromisoformat(v_match["retrieved_at"]) if v_match["retrieved_at"] else datetime.utcnow()
                    )
                    db.add(vuln_db)
                    db.commit()
                    db.refresh(vuln_db)
                
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    project_id=project_id,
                    component_purl=purl,
                    vulnerability_id=vuln_db.vulnerability_id,
                    severity=vuln_db.severity_level or "UNKNOWN",
                    cvss=vuln_db.cvss_score,
                    affected=True,
                    evidence=f"Source: {vuln_source}"
                )
                scan.security_findings.append(finding)
                
                c_vuln = {
                    "cve_id": vuln_db.vulnerability_id,
                    "cvss_score": vuln_db.cvss_score,
                    "severity": vuln_db.severity_level,
                    "affected_versions": vuln_db.affected_versions,
                    "fixed_versions": vuln_db.fixed_versions,
                    "description": vuln_db.summary
                }
                comp_vulns.append(c_vuln)
            
            purl_to_vulns[purl] = comp_vulns
            purl_to_comp_obj[purl] = comp_model
            processed_components.append(comp_model)
            
            graph_node_data = dict(comp_data)
            graph_node_data["vulnerabilities"] = comp_vulns
            components_for_graph.append(graph_node_data)
        
        update_progress("GRAPH_ANALYSIS", f"Component profiling complete. {len(processed_components)} components analysed.", 45)
        
        # 3. BUILD ATTACK GRAPH & BLAST RADIUS (Engines 30, 31)
        update_progress("GRAPH_ANALYSIS", "Building Dependency Attack Graph...", 50)
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
                    
        graph_data = build_dependency_graph(components_for_graph, relations)
        
        # Save relations in Dependency table
        for edge in graph_data["edges"]:
            dep_rel = Dependency(
                sbom_id=0, # Will be set post-SBOM insertion
                component_purl=edge["target"],
                dependent_purl=edge["source"]
            )
            db.add(dep_rel)
            
        # 4. RISK PRIORITIZATION & BLAST RADIUS CALCULATION (Engines 31, 33, 34, 37, 39, 40)
        update_progress("RISK_ANALYSIS", "Calculating Blast Radius, VEX Context, and Risk scores...", 60)
        for comp_data in components_for_graph:
            purl = comp_data["purl"]
            comp_model = purl_to_comp_obj[purl]
            
            # Blast Radius (Engine 31)
            blast_radius_res = calculate_blast_radius(purl, graph_data["nodes"], graph_data["edges"])
            
            # Contextual Security & VEX (Engine 33 / 34)
            comp_vulns = purl_to_vulns[purl]
            contextual_security_res = evaluate_contextual_security(comp_data, comp_vulns)
            
            # Risk Prioritization (Engine 37)
            anomaly_info = {"anomaly_score": comp_data["anomaly_score"]}
            risk_res = prioritize_risk(comp_data, comp_vulns, blast_radius_res, anomaly_info)
            comp_data["risk_score"] = risk_res["risk_score"]
            
            # Write Risk Assessment Record
            risk_desc = generate_security_explanation(comp_data, comp_vulns, risk_res["risk_score"], blast_radius_res) # Engine 39
            risk_model = RiskAssessment(
                component_purl=purl,
                risk_score=risk_res["risk_score"],
                risk_level=risk_res["risk_level"],
                explanation=risk_desc,
                blast_radius_json=json.dumps(blast_radius_res),
                production_exposure=blast_radius_res["production_exposure"],
                risk_factors=json.dumps(risk_res.get("factors", [])),
                missing_signals=json.dumps(risk_res.get("missing_signals", [])),
                risk_calculation_version=risk_res.get("calculation_version", "prototype-v1")
            )
            scan.risk_assessments.append(risk_model)
            
            # Add Remediation Recommendations (Engine 40)
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
                
            # Policy Evaluation (Engine 48)
            if scan.current_stage != "POLICY_EVALUATION":
                update_progress("POLICY_EVALUATION", "Evaluating Security Policies...", 70)
            policy_eval_res = evaluate_policy(comp_data, comp_vulns, risk_res["risk_score"], policy_rules)
            comp_data["policy_action"] = policy_eval_res["action"]
            comp_data["policy_reasons"] = policy_eval_res["reasons"]
            comp_data["remediation_recommendation"] = remediation_res
            
            # Trigger Automatic Alerts & Tickets (Engines 51, 52)
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
                
                # Ticket creation for CRITICAL/HIGH findings
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
                    log(f"Auto-created ticket {ticket_id} for package '{comp_data['name']}' due to {risk_res['risk_level']} risk level.")
                    
        # 5. SBOM COMPILING, SIGNING & VALIDATION (Engines 11, 12, 13, 14, 29)
        update_progress("SBOM_GENERATION", "Compiling and validating SBOM documents...", 80)
        # Compile relations list for SBOM
        cdx_relations = {}
        for edge in graph_data["edges"]:
            s = edge["source"]
            t = edge["target"]
            if s not in cdx_relations:
                cdx_relations[s] = []
            cdx_relations[s].append(t)
            
        cyclonedx_sbom = generate_cyclonedx(project.name, components_for_graph, cdx_relations)
        raw_json_str = json.dumps(cyclonedx_sbom, indent=2)
        
        # Calculate file integrity hash and sign SBOM (Engine 29)
        file_hash = hashlib.sha256(raw_json_str.encode("utf-8")).hexdigest()
        signature_str = sign_sbom(cyclonedx_sbom)
        verification_status = verify_sbom_signature(cyclonedx_sbom, signature_str)
        
        # Validate generated SBOM (Engine 13)
        is_valid, validation_errors = validate_sbom(cyclonedx_sbom)
        if not is_valid:
            log(f"SBOM Validation WARNING: {validation_errors}")
            
        # Write SBOM Record
        sbom_model = SBOM(
            scan_id=scan_id,
            project_id=project_id,
            format="CycloneDX",
            version="1.4",
            raw_json=raw_json_str,
            file_hash=file_hash,
            signature=signature_str,
            verification_status=verification_status
=======
        # 3. BUILD ATTACK GRAPH & BLAST RADIUS
        graph_data, pending_dependencies = _run_graph_and_risk_phase(
            project_id, scan, project, components_for_graph, purl_to_vulns, discovery_results, policy_rules, logs
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92
        )
        
        # 4. SBOM COMPILING, SIGNING & VALIDATION
        sbom_model, cyclonedx_sbom, quality_score_res = _run_sbom_compilation_phase(
            project_id, scan_id, project, components_for_graph, processed_components, graph_data, pending_dependencies, logs, db
        )
        
        # 5. POST SCAN PHASE (GATES, HISTORY, DIFF, COMPLETED STATUS)
        _run_post_scan_phase(
            project_id, scan, project, sbom_model, cyclonedx_sbom, quality_score_res, components_for_graph, logs, db
        )
        db.add(audit_rec)
        
        update_progress("FINALIZING", f"Scan complete. Gate decision: {gate_res['status']}.", 100, "COMPLETED")
        scan.status = "COMPLETED"
        scan.completed_at = datetime.utcnow()
        scan.log = "\n".join(logs)
        db.commit()
        
    except Exception as e:
        err_msg = traceback.format_exc()
        try:
            update_progress("FAILED", f"Pipeline error: {str(e)}", scan.overall_progress, "FAILED")
        except Exception:
            pass
        scan.status = "FAILED"
        scan.completed_at = datetime.utcnow()
        scan.log = "\n".join(logs) + f"\n{err_msg}"
        db.commit()
        
        audit_rec = AuditLog(
            username=scan.triggered_by,
            action="scan_failed",
            details=f"Failed scan {scan_id} for project '{project.name}': {str(e)}",
            ip_address="127.0.0.1"
        )
        db.add(audit_rec)
        db.commit()
