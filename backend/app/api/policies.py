from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import Policy, AuditLog
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/policies", tags=["Policies"])

class PolicyCreate(BaseModel):
    name: str
    rule_type: str # CVSS_THRESHOLD, AI_ANOMALY, FORBIDDEN_LICENSE, UNKNOWN_VERSION
    rule_condition: str # e.g. ">= 9.0", ">= 80", "FORBIDDEN", "UNKNOWN"
    action: str # BLOCK, REVIEW, PASS
    is_active: Optional[bool] = True

class PolicyUpdate(BaseModel):
    name: Optional[str]
    rule_type: Optional[str]
    rule_condition: Optional[str]
    action: Optional[str]
    is_active: Optional[bool]

@router.get("")
def list_policies(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    _ = current_user
    # Make sure some default policies exist for the demo if none are present
    policies = db.query(Policy).all()
    if not policies:
        defaults = [
            Policy(name="Block Critical CVSS", rule_type="CVSS_THRESHOLD", rule_condition=">= 9.0", action="BLOCK", is_active=True),
            Policy(name="Review High CVSS", rule_type="CVSS_THRESHOLD", rule_condition=">= 7.0", action="REVIEW", is_active=True),
            Policy(name="Review AI Anomalies", rule_type="AI_ANOMALY", rule_condition=">= 80", action="REVIEW", is_active=True),
            Policy(name="Block Copyleft Licenses", rule_type="FORBIDDEN_LICENSE", rule_condition="FORBIDDEN", action="BLOCK", is_active=True),
            Policy(name="Review Unknown Versions", rule_type="UNKNOWN_VERSION", rule_condition="UNKNOWN", action="REVIEW", is_active=True)
        ]
        db.add_all(defaults)
        db.commit()
        policies = db.query(Policy).all()
    return policies

@router.post("", status_code=status.HTTP_201_CREATED)
def create_policy(data: PolicyCreate, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    policy = Policy(
        name=data.name,
        rule_type=data.rule_type,
        rule_condition=data.rule_condition,
        action=data.action,
        is_active=data.is_active
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    
    audit_rec = AuditLog(
        username=current_user.username,
        action="create_policy",
        details=f"Created policy '{data.name}' ({data.rule_type}: {data.rule_condition} -> {data.action})",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()
    
    return policy

@router.put("/{policy_id}")
def update_policy(policy_id: int, data: PolicyUpdate, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    policy = db.query(Policy).get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    for k, v in data.dict(exclude_unset=True).items():
        setattr(policy, k, v)
        
    db.commit()
    db.refresh(policy)
    
    audit_rec = AuditLog(
        username=current_user.username,
        action="update_policy",
        details=f"Updated policy {policy_id} ('{policy.name}')",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()
    
    return policy

@router.delete("/{policy_id}")
def delete_policy(policy_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    policy = db.query(Policy).get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    name = policy.name
    db.delete(policy)
    
    audit_rec = AuditLog(
        username=current_user.username,
        action="delete_policy",
        details=f"Deleted policy '{name}'",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()
    
    return {"message": "Policy deleted successfully"}
