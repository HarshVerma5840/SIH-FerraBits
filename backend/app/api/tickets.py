from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import Ticket, AuditLog, SecurityFinding, SBOMComponent, Project
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import func
import uuid

router = APIRouter(prefix="/tickets", tags=["Tickets"])

class TicketUpdate(BaseModel):
    status: Optional[str] # OPEN, IN_PROGRESS, RESOLVED
    assignee: Optional[str]

@router.get("")
def list_tickets(project_id: Optional[int] = None, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    query = db.query(Ticket)
    if project_id:
        query = query.filter_by(project_id=project_id)
    return query.all()

@router.put("/{ticket_id}")
def update_ticket(ticket_id: str, data: TicketUpdate, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    # Find ticket by ticket_id string
    ticket = db.query(Ticket).filter_by(ticket_id=ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
        
    if data.status:
        ticket.status = data.status.upper()
    if data.assignee:
        ticket.assignee = data.assignee
        
    db.commit()
    db.refresh(ticket)
    
    audit_rec = AuditLog(
        username=current_user.username,
        action="update_ticket",
        details=f"Updated ticket '{ticket_id}' status to '{ticket.status}'",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()
    
    return ticket

class GenerateTicketsRequest(BaseModel):
    project_id: int
    scan_id: int

@router.post("/generate")
def generate_tickets(req: GenerateTicketsRequest, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    
    # Verify project exists
    project = db.query(Project).get(req.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Fetch all unresolved security findings for this scan
    findings = db.query(SecurityFinding).filter(
        SecurityFinding.scan_id == req.scan_id,
        SecurityFinding.status == "AFFECTED"
    ).all()
    
    if not findings:
        return {"status": "success", "message": "No vulnerabilities found to generate tickets for.", "count": 0}
        
    # Group findings by component_purl
    grouped_findings = {}
    for f in findings:
        purl = f.component_purl
        if purl not in grouped_findings:
            grouped_findings[purl] = []
        grouped_findings[purl].append(f)
        
    tickets_created = 0
    
    for purl, group in grouped_findings.items():
        # Look up component name and version from SBOMComponent
        component = db.query(SBOMComponent).filter_by(purl=purl).first()
        comp_name = component.name if component else purl.split('@')[0].split('/')[-1]
        comp_version = component.version if component else (purl.split('@')[1] if '@' in purl else "unknown")
        
        # Determine highest severity
        severities = [f.severity.upper() for f in group]
        highest_severity = "LOW"
        if "CRITICAL" in severities:
            highest_severity = "CRITICAL"
        elif "HIGH" in severities:
            highest_severity = "HIGH"
        elif "MEDIUM" in severities:
            highest_severity = "MEDIUM"
            
        # Determine max cvss
        max_cvss = max([f.cvss for f in group if f.cvss is not None] or [0.0])
        
        # Build minimal description
        description = f"Action Required: Remediate {len(group)} vulnerabilities found in {comp_name}."
        recommendation = f"Upgrade {comp_name} to the latest secure version."
        
        # Create ticket
        # Generate a short ID (e.g., SEC-XXXX)
        short_id = f"SEC-{str(uuid.uuid4())[:6].upper()}"
        
        # Check if a ticket for this component already exists for this project that is OPEN/IN_PROGRESS
        existing_ticket = db.query(Ticket).filter(
            Ticket.project_id == req.project_id,
            Ticket.component_name == comp_name,
            Ticket.status.in_(["OPEN", "IN_PROGRESS"])
        ).first()
        
        if existing_ticket:
            # Update existing ticket description rather than creating duplicate
            existing_ticket.description = description
            existing_ticket.severity = highest_severity
            existing_ticket.risk_score = max_cvss * 10
            existing_ticket.recommendation = recommendation
        else:
            new_ticket = Ticket(
                ticket_id=short_id,
                project_id=req.project_id,
                component_name=comp_name,
                component_version=comp_version,
                severity=highest_severity,
                risk_score=max_cvss * 10,
                description=description,
                recommendation=recommendation,
                status="OPEN"
            )
            db.add(new_ticket)
            tickets_created += 1
            
    db.commit()
    
    return {
        "status": "success", 
        "message": f"Successfully generated/updated tickets for {len(grouped_findings)} vulnerable components.",
        "count": tickets_created
    }
