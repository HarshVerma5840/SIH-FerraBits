import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import (
    Project, Scan, SBOM, SBOMComponent, Dependency, SBOMVersion, SBOMDiff,
    Vulnerability, RiskAssessment, Anomaly, RemediationRecommendation
)
from backend.app.engines import run_whatif_simulation, build_dependency_graph, OFFLINE_VULN_DB
from pydantic import BaseModel
from typing import List, Optional

router = APIRouter(prefix="/projects", tags=["Projects"])

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = ""

def _get_scan_summary(latest_scan, db):
    if not latest_scan:
        return 0, 0, "LOW", 100
    vuln_count = db.query(Vulnerability).join(SBOMComponent.vulnerabilities).join(SBOM).filter(SBOM.scan_id == latest_scan.id).count()
    risk_score = 0
    risk_level = "LOW"
    assessments = db.query(RiskAssessment).filter_by(scan_id=latest_scan.id).all()
    if assessments:
        risk_score = max([a.risk_score for a in assessments] or [0])
        if risk_score >= 85:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
    quality_score = 100
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if sbom and sbom.raw_json:
        try:
            from backend.app.engines.sbom_engine import calculate_quality_score, normalize_sbom
            normalized = normalize_sbom(json.loads(sbom.raw_json))
            quality_score = calculate_quality_score(normalized).get("score", 100)
        except Exception:
            pass
    return vuln_count, risk_score, risk_level, quality_score

def _load_assessments_and_remediations(latest_scan, db):
    assessments = db.query(RiskAssessment).filter_by(scan_id=latest_scan.id).all()
    assess_map = {a.component_purl: a for a in assessments}
    risk_summary = {"score": 0, "level": "LOW"}
    if assessments:
        max_score = max([a.risk_score for a in assessments] or [0])
        level = "LOW"
        if max_score >= 85: level = "CRITICAL"
        elif max_score >= 60: level = "HIGH"
        elif max_score >= 30: level = "MEDIUM"
        risk_summary = {"score": max_score, "level": level}
        
    rems = db.query(RemediationRecommendation).filter_by(scan_id=latest_scan.id).all()
    remediations = [{
        "purl": r.component_purl,
        "current_version": r.current_version,
        "recommended_version": r.recommended_version,
        "upgrade_impact": r.upgrade_impact
    } for r in rems]
    return assess_map, risk_summary, remediations

def _load_anomalies_and_components(latest_scan, sbom, assess_map, db):
    db_components = db.query(SBOMComponent).filter_by(sbom_id=sbom.id).all()
    anoms = db.query(Anomaly).filter_by(scan_id=latest_scan.id).all()
    anoms_map = {an.component_purl: an for an in anoms}
    anomalies = [{
        "purl": an.component_purl,
        "score": an.anomaly_score,
        "probability": an.anomaly_probability,
        "classification": an.classification,
        "indicators": json.loads(an.indicators_json)
    } for an in anoms]
    
    components = []
    vulnerabilities = []
    for c in db_components:
        c_vulns = [{
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "severity": v.severity,
            "description": v.description
        } for v in c.vulnerabilities]
        vulnerabilities.extend(c_vulns)
        
        c_assess = assess_map.get(c.purl)
        c_anom = anoms_map.get(c.purl)
        
        components.append({
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "license": c.license,
            "depth": c.depth,
            "direct": c.direct,
            "source_file": c.source_file,
            "confidence": c.confidence,
            "risk_score": c_assess.risk_score if c_assess else 0,
            "risk_level": c_assess.risk_level if c_assess else "LOW",
            "explanation": c_assess.explanation if c_assess else "No risk assessed.",
            "anomaly_score": c_anom.anomaly_score if c_anom else 0,
            "vulnerabilities": c_vulns
        })
        
    quality_score = 100
    try:
        from backend.app.engines.sbom_engine import calculate_quality_score, normalize_sbom
        quality_score = calculate_quality_score(components).get("score", 100)
    except Exception:
        pass
        
    return components, vulnerabilities, anomalies, quality_score

def _load_project_scan_details(latest_scan, db):
    components = []
    vulnerabilities = []
    anomalies = []
    remediations = []
    risk_summary = {"score": 0, "level": "LOW"}
    quality_score = 100
    
    if not latest_scan:
        return components, vulnerabilities, anomalies, remediations, risk_summary, quality_score
        
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if not sbom:
        return components, vulnerabilities, anomalies, remediations, risk_summary, quality_score
        
    assess_map, risk_summary, remediations = _load_assessments_and_remediations(latest_scan, db)
    components, vulnerabilities, anomalies, quality_score = _load_anomalies_and_components(latest_scan, sbom, assess_map, db)
    
    return components, vulnerabilities, anomalies, remediations, risk_summary, quality_score

@router.get("")
def list_projects(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    projects = db.query(Project).all()
    out = []
    for p in projects:
        latest_scan = db.query(Scan).filter_by(project_id=p.id).order_by(Scan.created_at.desc()).first()
        vuln_count, risk_score, risk_level, quality_score = _get_scan_summary(latest_scan, db)
        out.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "created_at": p.created_at,
            "latest_scan_status": latest_scan.status if latest_scan else "NEVER_SCANNED",
            "latest_scan_id": latest_scan.id if latest_scan else None,
            "vulnerability_count": vuln_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "quality_score": quality_score
        })
    return out

@router.post("", status_code=status.HTTP_201_CREATED, responses={400: {"description": "Project with this name already exists"}})
def create_project(data: ProjectCreate, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    existing = db.query(Project).filter_by(name=data.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Project with this name already exists")
    p = Project(name=data.name, description=data.description)
    db.add(p)
    db.commit()
    db.refresh(p)
    return p

@router.get("/{project_id}", responses={404: {"description": "Project not found"}})
def get_project_details(project_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    project = db.query(Project).get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    latest_scan = db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc()).first()
    components, vulnerabilities, anomalies, remediations, risk_summary, quality_score = _load_project_scan_details(latest_scan, db)
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at,
        "latest_scan_id": latest_scan.id if latest_scan else None,
        "latest_scan_status": latest_scan.status if latest_scan else "NEVER_SCANNED",
        "latest_scan_logs": latest_scan.log if latest_scan else "",
        "components": components,
        "vulnerabilities": vulnerabilities,
        "anomalies": anomalies,
        "remediations": remediations,
        "risk_summary": risk_summary,
        "quality_score": quality_score
    }

@router.get("/{project_id}/history")
def get_project_history(project_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    versions = db.query(SBOMVersion).filter_by(project_id=project_id).order_by(SBOMVersion.version_number.desc()).all()
    out = []
    for v in versions:
        sbom = db.query(SBOM).get(v.sbom_id)
        scan = db.query(Scan).get(sbom.scan_id) if sbom else None
        
        comp_count = 0
        if sbom:
            comp_count = db.query(SBOMComponent).filter_by(sbom_id=sbom.id).count()
            
        out.append({
            "version_number": v.version_number,
            "sbom_id": v.sbom_id,
            "created_at": v.created_at,
            "components_count": comp_count,
            "scan_id": scan.id if scan else None,
            "scan_triggered_by": scan.triggered_by if scan else "System"
        })
    return out

@router.get("/{project_id}/diff/{base_id}/{head_id}", responses={404: {"description": "SBOM records not found for diff comparison"}})
def get_project_diff(project_id: int, base_id: int, head_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    diff = db.query(SBOMDiff).filter_by(project_id=project_id, base_scan_id=base_id, head_scan_id=head_id).first()
    # Alternate check in case IDs are swapped or it's head/base
    if not diff:
        diff = db.query(SBOMDiff).filter_by(project_id=project_id, base_scan_id=head_id, head_scan_id=base_id).first()
        
    if not diff:
        # Generate inline diff if records aren't generated
        base_sbom = db.query(SBOM).get(base_id)
        head_sbom = db.query(SBOM).get(head_id)
        if not base_sbom or not head_sbom:
            raise HTTPException(status_code=404, detail="SBOM records not found for diff comparison")
            
        from backend.app.engines import normalize_sbom
        base_norm = normalize_sbom(json.loads(base_sbom.raw_json))
        head_norm = normalize_sbom(json.loads(head_sbom.raw_json))
        
        base_map = {c["purl"]: c for c in base_norm}
        head_map = {c["purl"]: c for c in head_norm}
        
        added = [c for c in head_norm if c["purl"] not in base_map]
        removed = [c for c in base_norm if c["purl"] not in head_map]
        updated = []
        for purl, c in head_map.items():
            if purl in base_map:
                prev = base_map[purl]
                if c["version"] != prev["version"] or c["license"] != prev["license"]:
                    updated.append({
                        "name": c["name"],
                        "old_version": prev["version"],
                        "new_version": c["version"],
                        "old_license": prev["license"],
                        "new_license": c["license"]
                    })
        return {
            "added": added,
            "removed": removed,
            "updated": updated
        }
        
    return {
        "added": json.loads(diff.added_json),
        "removed": json.loads(diff.removed_json),
        "updated": json.loads(diff.updated_json)
    }

@router.get("/{project_id}/graph", responses={404: {"description": "No scan data or SBOM found for graph generation"}})
def get_project_graph(project_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    latest_scan = db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc()).first()
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No scan data found for graph generation")
        
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if not sbom:
        raise HTTPException(status_code=404, detail="No SBOM found for graph generation")
        
    db_components = db.query(SBOMComponent).filter_by(sbom_id=sbom.id).all()
    db_relations = db.query(Dependency).filter_by(sbom_id=sbom.id).all()
    
    # Map assessments
    assessments = db.query(RiskAssessment).filter_by(scan_id=latest_scan.id).all()
    assess_map = {a.component_purl: a for a in assessments}
    
    # Map anomalies
    anoms = db.query(Anomaly).filter_by(scan_id=latest_scan.id).all()
    anom_map = {an.component_purl: an for an in anoms}
    
    # Map components to node list
    components = []
    for c in db_components:
        assess = assess_map.get(c.purl)
        anom = anom_map.get(c.purl)
        components.append({
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "type": c.component_type,
            "license": c.license,
            "direct": c.direct,
            "risk_score": assess.risk_score if assess else 0,
            "vulnerabilities": c.vulnerabilities, # object representation
            "anomaly_score": anom.anomaly_score if anom else 0
        })
        
    # Standard format relations
    relations = {}
    for r in db_relations:
        p = r.dependent_purl
        c = r.component_purl
        if p not in relations:
            relations[p] = []
        relations[p].append(c)
        
    graph = build_dependency_graph(components, relations)
    return graph

class WhatIfRequest(BaseModel):
    upgrade_purl: str
    target_version: str

@router.post("/{project_id}/whatif", responses={404: {"description": "No scan data or SBOM found for simulation"}})
def simulate_whatif(project_id: int, data: WhatIfRequest, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    latest_scan = db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc()).first()
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No scan data found for simulation")
        
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if not sbom:
        raise HTTPException(status_code=404, detail="No SBOM found for simulation")
        
    db_components = db.query(SBOMComponent).filter_by(sbom_id=sbom.id).all()
    components = []
    for c in db_components:
        components.append({
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "type": c.component_type,
            "direct": c.direct
        })
        
    simulation = run_whatif_simulation(components, data.upgrade_purl, data.target_version, OFFLINE_VULN_DB)
    return simulation
