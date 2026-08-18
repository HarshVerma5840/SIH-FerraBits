from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import Vulnerability, RiskAssessment, AuditLog
from pydantic import BaseModel

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

class VexUpdateRequest(BaseModel):
    component_purl: str
    scan_id: int
    vex_status: str # AFFECTED, NOT_AFFECTED, UNDER_INVESTIGATION, FIXED
    justification: str

@router.get("")
def list_vulnerabilities(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    vulns = db.query(Vulnerability).all()
    out = []
    for v in vulns:
        # Count affected packages
        # Using many-to-many relationship
        affected_comps = len(v.components)
        out.append({
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "severity": v.severity,
            "description": v.description,
            "affected_versions": v.affected_versions,
            "fixed_versions": v.fixed_versions,
            "affected_packages_count": affected_comps
        })
    return out

@router.put("/vex")
def update_vex_status(data: VexUpdateRequest, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    assess = db.query(RiskAssessment).filter_by(
        scan_id=data.scan_id,
        component_purl=data.component_purl
    ).first()
    
    if not assess:
        raise HTTPException(status_code=404, detail="Risk assessment entry not found for this component scan")
        
    # Update explanation/vex fields
    # We append VEX details to the assessment explanation
    old_explanation = assess.explanation
    assess.explanation = f"[VEX STATUS: {data.vex_status}] Reason: {data.justification}. (History: {old_explanation})"
    
    # Audit log
    audit_rec = AuditLog(
        username=current_user.username,
        action="update_vex",
        details=f"Updated VEX context of component '{data.component_purl}' in scan {data.scan_id} to '{data.vex_status}'",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()
    
    return {
        "status": "SUCCESS",
        "message": f"VEX status updated to {data.vex_status} successfully"
    }
