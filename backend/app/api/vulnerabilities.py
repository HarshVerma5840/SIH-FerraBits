from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import (
    Vulnerability, RiskAssessment, AuditLog, SecurityFinding,
    SBOMComponent, SBOM
)
from backend.app.engines.ai_engine.llm_explanation import explain_finding, is_llm_available
from pydantic import BaseModel
import json

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


class VexUpdateRequest(BaseModel):
    component_purl: str
    scan_id: int
    vex_status: str  # AFFECTED, NOT_AFFECTED, UNDER_INVESTIGATION, FIXED
    justification: str


def _resolve_component(db: Session, component_purl: str, scan_id: int) -> SBOMComponent | None:
    """
    Look up the SBOMComponent for a given purl + scan.
    Components are linked to SBOMs which are linked to scans.
    """
    sbom = db.query(SBOM).filter_by(scan_id=scan_id).first()
    if not sbom:
        return None
    return db.query(SBOMComponent).filter_by(
        sbom_id=sbom.id, purl=component_purl
    ).first()


def _serialize_finding(f: SecurityFinding, db: Session) -> dict:
    """Serialize a SecurityFinding into the normalized finding schema."""
    v = f.vulnerability
    comp = _resolve_component(db, f.component_purl, f.scan_id)
    risk = db.query(RiskAssessment).filter_by(
        scan_id=f.scan_id, component_purl=f.component_purl
    ).first()

    risk_factors: list = []
    if risk and risk.risk_factors:
        try:
            risk_factors = json.loads(risk.risk_factors)
        except Exception:
            pass

    # Parse vuln fields safely
    aliases: list = []
    affected_versions: list = []
    fixed_versions: list = []
    if v:
        try:
            aliases = json.loads(v.aliases) if v.aliases else []
        except Exception:
            pass
        try:
            affected_versions = json.loads(v.affected_versions) if v.affected_versions else []
        except Exception:
            pass
        try:
            fixed_versions = json.loads(v.fixed_versions) if v.fixed_versions else []
        except Exception:
            pass

    # Determine vuln source from evidence field
    vuln_source = "OSV"
    if f.evidence and "Source:" in f.evidence:
        vuln_source = f.evidence.replace("Source:", "").strip()

    return {
        "finding_id": f.finding_id,
        "scan_id": f.scan_id,
        "component": {
            "name": comp.name if comp else "UNKNOWN",
            "version": comp.version if comp else "UNKNOWN",
            "ecosystem": comp.ecosystem if comp else "UNKNOWN",
            "purl": f.component_purl,
            "version_source": comp.version_source if comp else "UNKNOWN",
            "version_confidence": comp.version_confidence if comp else "UNKNOWN",
        },
        "vulnerability": {
            "id": v.vulnerability_id if v else "UNKNOWN",
            "aliases": aliases,
            "summary": v.summary if v else "",
            "severity": f.severity,
            "cvss": f.cvss,
            "affected_versions": affected_versions,
            "fixed_versions": fixed_versions,
            "exploit_status": "KNOWN" if (v and v.known_exploited) else "UNKNOWN",
            "source": vuln_source,
            "source_url": v.source_url if v else None,
        },
        "environment_context": {
            "environment": f.environment,
            "internet_exposed": f.internet_exposed,
            "business_criticality": f.business_criticality,
        },
        "risk": {
            "score": risk.risk_score if risk else 0,
            "severity": risk.risk_level if risk else "UNKNOWN",
            "factors": risk_factors,
        },
        "status": f.status,
    }


@router.get("")
<<<<<<< HEAD
def list_vulnerabilities(
    scan_id: int | None = None,
    project_id: int | None = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List all security findings.
    Optionally filter by scan_id or project_id.
    """
    q = db.query(SecurityFinding)
    if scan_id is not None:
        q = q.filter(SecurityFinding.scan_id == scan_id)
    if project_id is not None:
        q = q.filter(SecurityFinding.project_id == project_id)

    findings = q.order_by(SecurityFinding.created_at.desc()).all()
    return [_serialize_finding(f, db) for f in findings]


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Retrieve a single SecurityFinding by its UUID.
    """
    f = db.query(SecurityFinding).filter_by(finding_id=finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return _serialize_finding(f, db)

=======
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
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92

@router.put("/vex")
def update_vex_status(
    data: VexUpdateRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update the VEX status of a specific finding."""
    assess = db.query(RiskAssessment).filter_by(
        scan_id=data.scan_id,
        component_purl=data.component_purl
    ).first()

    if not assess:
        raise HTTPException(
            status_code=404,
            detail="Risk assessment entry not found for this component scan"
        )

    old_explanation = assess.explanation or ""
    assess.explanation = (
        f"[VEX STATUS: {data.vex_status}] Reason: {data.justification}. "
        f"(History: {old_explanation})"
    )

    # Also update the SecurityFinding status
    findings = db.query(SecurityFinding).filter_by(
        scan_id=data.scan_id,
        component_purl=data.component_purl
    ).all()
    for f in findings:
        f.status = data.vex_status

    audit_rec = AuditLog(
        username=current_user.username,
        action="update_vex",
        details=(
            f"Updated VEX context of component '{data.component_purl}' "
            f"in scan {data.scan_id} to '{data.vex_status}'"
        ),
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()

    return {
        "status": "SUCCESS",
        "message": f"VEX status updated to {data.vex_status} successfully"
    }
@router.get("/findings/{finding_id}/explain")
def explain_finding_endpoint(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Generate a developer-friendly LLM explanation for a specific security finding.
    Uses Google Gemini (GEMINI_API_KEY env var) with a deterministic fallback.
    Security facts are read from the verified database record — the LLM cannot modify them.
    """
    f = db.query(SecurityFinding).filter_by(finding_id=finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    serialized = _serialize_finding(f, db)

    # Build dependency context from the component record
    comp = _resolve_component(db, f.component_purl, f.scan_id)
    dep_ctx = {
        "direct_dependency": comp.direct if comp else "unknown",
        "dependency_depth": comp.depth if comp else "unknown",
    }

    # Build the structured finding for the LLM — all facts from database
    llm_input = {
        "component": serialized["component"],
        "vulnerability": serialized["vulnerability"],
        "dependency_context": dep_ctx,
        "risk_context": serialized["risk"],
    }

    explanation = explain_finding(llm_input)
    return {
        "finding_id": finding_id,
        "llm_available": is_llm_available(),
        "explanation": explanation,
    }


@router.get("/ai-status")
def get_ai_status(current_user = Depends(get_current_user)):
    """Returns whether the LLM explanation service is configured."""
    return {
        "llm_available": is_llm_available(),
        "provider": "gemini-1.5-flash-8b" if is_llm_available() else None,
        "fallback": "deterministic",
    }
