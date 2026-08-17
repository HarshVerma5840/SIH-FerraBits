from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import AuditLog

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])

@router.get("")
def list_audit_logs(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
