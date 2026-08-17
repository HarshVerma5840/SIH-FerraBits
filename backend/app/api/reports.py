import json
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import Project, Scan, SBOM, SBOMComponent, RiskAssessment, Vulnerability, AuditLog
from backend.app.engines import generate_csv_report, generate_executive_json_report, generate_spdx, calculate_quality_score, normalize_sbom

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/project/{project_id}/executive")
def get_executive_report(project_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    project = db.query(Project).get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    latest_scan = db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc()).first()
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No scan data found to generate executive report")
        
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if not sbom:
         raise HTTPException(status_code=404, detail="No SBOM found for reporting")
         
    db_components = db.query(SBOMComponent).filter_by(sbom_id=sbom.id).all()
    assessments = db.query(RiskAssessment).filter_by(scan_id=latest_scan.id).all()
    
    # Extract components as list of dicts
    components_list = []
    vulnerabilities_list = []
    
    for c in db_components:
        components_list.append({
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "license": c.license,
            "supplier": c.supplier,
            "hash": c.hash_sha256
        })
        for v in c.vulnerabilities:
            vulnerabilities_list.append({
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "component_purl": c.purl
            })
            
    risk_assess_list = [{
        "component_purl": r.component_purl,
        "risk_level": r.risk_level
    } for r in assessments]
    
    quality_score = calculate_quality_score(components_list)
    
    rep = generate_executive_json_report(
        project, latest_scan, components_list, vulnerabilities_list, risk_assess_list, quality_score
    )
    return rep

@router.get("/project/{project_id}/csv")
def get_csv_report_file(project_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    project = db.query(Project).get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    latest_scan = db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc()).first()
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No scan data found")
        
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if not sbom:
        raise HTTPException(status_code=404, detail="No SBOM found")
        
    db_components = db.query(SBOMComponent).filter_by(sbom_id=sbom.id).all()
    assessments = db.query(RiskAssessment).filter_by(scan_id=latest_scan.id).all()
    
    components_list = []
    vulnerabilities_list = []
    for c in db_components:
        components_list.append({
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "license": c.license
        })
        for v in c.vulnerabilities:
            vulnerabilities_list.append({
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "component_purl": c.purl
            })
            
    risk_assess_list = [{
        "component_purl": r.component_purl,
        "risk_score": r.risk_score,
        "risk_level": r.risk_level
    } for r in assessments]
    
    csv_data = generate_csv_report(components_list, vulnerabilities_list, risk_assess_list)
    
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sbom_report_{project.name}.csv"}
    )

@router.get("/project/{project_id}/cyclonedx")
def download_cyclonedx_file(project_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    project = db.query(Project).get(project_id)
    latest_scan = db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc()).first()
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No scan data found")
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if not sbom:
        raise HTTPException(status_code=404, detail="No CycloneDX SBOM found")
        
    return Response(
        content=sbom.raw_json,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=cyclonedx_{project.name}.json"}
    )

@router.get("/project/{project_id}/spdx")
def download_spdx_file(project_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    project = db.query(Project).get(project_id)
    latest_scan = db.query(Scan).filter_by(project_id=project_id).order_by(Scan.created_at.desc()).first()
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No scan data found")
    sbom = db.query(SBOM).filter_by(scan_id=latest_scan.id).first()
    if not sbom:
        raise HTTPException(status_code=404, detail="No SBOM found")
        
    # Generate SPDX on the fly from CycloneDX JSON
    try:
        cdx = json.loads(sbom.raw_json)
        normalized = normalize_sbom(cdx)
        spdx_json = generate_spdx(project.name, normalized)
        return Response(
            content=json.dumps(spdx_json, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=spdx_{project.name}.json"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate SPDX representation: {str(e)}")
