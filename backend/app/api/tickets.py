from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import Ticket, AuditLog
from pydantic import BaseModel
from typing import Optional

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
