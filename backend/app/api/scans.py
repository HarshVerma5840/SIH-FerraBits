import os
import uuid
import zipfile
import shutil
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form
from sqlalchemy.orm import Session
from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import Scan, Project, AuditLog
from backend.app.services.scan_pipeline import run_scan_pipeline
from pydantic import BaseModel

router = APIRouter(prefix="/scans", tags=["Scans"])

# Temporary workspace directory for scanning uploads
TEMP_SCAN_BASE = r"C:\Users\5430\.gemini\antigravity\temp_scans"

class LocalScanRequest(BaseModel):
    project_id: int
    directory_path: str

@router.post("/upload")
def upload_and_scan(
    background_tasks: BackgroundTasks,
    project_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    project = db.query(Project).get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported for scanning uploads")
        
    # Generate unique folder paths
    scan_uuid = uuid.uuid4().hex
    target_dir = os.path.join(TEMP_SCAN_BASE, scan_uuid)
    os.makedirs(target_dir, exist_ok=True)
    
    zip_path = os.path.join(target_dir, "upload.zip")
    
    # Save uploaded file
    try:
        with open(zip_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
            
        # Extract files
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(target_dir)
            
        # Remove zip file after extraction
        os.remove(zip_path)
    except Exception as e:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Failed to extract uploaded archive: {str(e)}")
        
    # Create Scan Record
    scan = Scan(
        project_id=project_id,
        status="PENDING",
        triggered_by=current_user.username
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Audit log
    audit_rec = AuditLog(
        username=current_user.username,
        action="scan_triggered",
        details=f"Triggered scan {scan.id} via file upload for project '{project.name}'",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()
    
    # Schedule scan pipeline execution in background
    background_tasks.add_task(run_scan_pipeline_and_cleanup, project_id, scan.id, target_dir, db)
    
    return {
        "scan_id": scan.id,
        "status": "PENDING",
        "message": "Scan scheduled in background"
    }

@router.post("/local")
def scan_local_directory(
    background_tasks: BackgroundTasks,
    data: LocalScanRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    project = db.query(Project).get(data.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    if not os.path.exists(data.directory_path):
        raise HTTPException(status_code=404, detail=f"Directory path '{data.directory_path}' does not exist on disk")
        
    # Create Scan Record
    scan = Scan(
        project_id=data.project_id,
        status="PENDING",
        triggered_by=current_user.username
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Audit log
    audit_rec = AuditLog(
        username=current_user.username,
        action="scan_triggered",
        details=f"Triggered scan {scan.id} for local path '{data.directory_path}' on project '{project.name}'",
        ip_address="127.0.0.1"
    )
    db.add(audit_rec)
    db.commit()
    
    # Schedule scan pipeline execution in background (no cleanup needed for local folder)
    background_tasks.add_task(run_scan_pipeline, data.project_id, scan.id, data.directory_path, db)
    
    return {
        "scan_id": scan.id,
        "status": "PENDING",
        "message": f"Scan scheduled for local directory: {data.directory_path}"
    }

@router.get("/{scan_id}/status")
def get_scan_status(scan_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at
    }

@router.get("/{scan_id}/logs")
def get_scan_logs(scan_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"logs": scan.log or ""}

def run_scan_pipeline_and_cleanup(project_id, scan_id, target_dir, db):
    try:
        run_scan_pipeline(project_id, scan_id, target_dir, db)
    finally:
        # Cleanup uploaded files after scanning completes
        shutil.rmtree(target_dir, ignore_errors=True)
