"""
GitHub Integration API Endpoints
Handles GitHub App repo listing, branch listing, and webhook event processing.
"""
import os
import uuid
import hmac
import hashlib
import json
import shutil
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.app.core.security import get_db, get_current_user
from backend.app.models.database import (
    Scan, Project, Repository, AuditLog, GitHubInstallation
)
from backend.app.services.github_app import (
    get_installation_token, list_accessible_repos, list_branches
)
from backend.app.services.code_fetcher import CodeFetcher
from backend.app.services.scan_pipeline import run_scan_pipeline

router = APIRouter(prefix="/github", tags=["GitHub Integration"])

# Optional: GitHub webhook secret for payload verification
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")


# ──────────────────────────── Request Models ────────────────────────────

class InstallationReposRequest(BaseModel):
    installation_id: str


class BranchListRequest(BaseModel):
    installation_id: str
    owner: str
    repo: str


# ──────────────────────────── Repo & Branch Listing ────────────────────────────

@router.post("/installations/repos")
def get_installation_repos(
    data: InstallationReposRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    List all repositories accessible via a GitHub App installation.
    """
    try:
        token = get_installation_token(data.installation_id)
        repos = list_accessible_repos(token)

        return {
            "installation_id": data.installation_id,
            "total_repos": len(repos),
            "repositories": [
                {
                    "full_name": r["full_name"],
                    "owner": r["owner"]["login"],
                    "name": r["name"],
                    "private": r["private"],
                    "default_branch": r.get("default_branch", "main"),
                    "html_url": r["html_url"]
                }
                for r in repos
            ]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {str(e)}")


@router.post("/installations/branches")
def get_repo_branches(
    data: BranchListRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    List all branches for a specific repository via a GitHub App installation.
    """
    try:
        token = get_installation_token(data.installation_id)
        branches = list_branches(token, data.owner, data.repo)

        return {
            "owner": data.owner,
            "repo": data.repo,
            "branches": branches
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {str(e)}")


# ──────────────────────────── Webhook Handler ────────────────────────────

def _verify_webhook_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify the GitHub webhook payload signature using HMAC-SHA256."""
    if not GITHUB_WEBHOOK_SECRET:
        # If no secret is configured, skip verification (dev mode)
        return True

    if not signature_header:
        return False

    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature_header)


@router.post("/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Receive GitHub webhook events (push, installation, etc.) and auto-trigger scans.
    
    Supported events:
    - push: Auto-scan the repository on code changes
    - installation: Track new GitHub App installations
    """
    # 1. Read raw body for signature verification
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not _verify_webhook_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 2. Parse event type and payload
    event_type = request.headers.get("X-GitHub-Event", "")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # 3. Handle installation events (track new installs)
    if event_type == "installation":
        action = payload.get("action", "")
        installation = payload.get("installation", {})
        installation_id = str(installation.get("id", ""))
        account = installation.get("account", {})

        if action == "created":
            # Save new installation record
            existing = db.query(GitHubInstallation).filter_by(installation_id=installation_id).first()
            if not existing:
                new_install = GitHubInstallation(
                    installation_id=installation_id,
                    account_login=account.get("login", "unknown"),
                    account_type=account.get("type", "User")
                )
                db.add(new_install)
                db.commit()

            return {"status": "installation_tracked", "installation_id": installation_id}

        elif action == "deleted":
            existing = db.query(GitHubInstallation).filter_by(installation_id=installation_id).first()
            if existing:
                db.delete(existing)
                db.commit()
            return {"status": "installation_removed", "installation_id": installation_id}

    # 4. Handle push events (auto-trigger scan)
    if event_type == "push":
        repo_data = payload.get("repository", {})
        repo_url = repo_data.get("html_url", "")
        repo_full_name = repo_data.get("full_name", "")
        branch_ref = payload.get("ref", "")  # e.g., "refs/heads/main"
        branch = branch_ref.replace("refs/heads/", "") if branch_ref.startswith("refs/heads/") else branch_ref
        installation_id = str(payload.get("installation", {}).get("id", ""))

        if not repo_url or not installation_id:
            return {"status": "skipped", "reason": "Missing repository or installation data"}

        # Look up project via the Repository model (option 3 from plan)
        repo_record = db.query(Repository).filter(
            Repository.url.contains(repo_full_name)
        ).first()

        if not repo_record:
            # No project linked to this repo — skip
            return {
                "status": "skipped",
                "reason": f"No SBOMGuard project linked to repository '{repo_full_name}'. "
                          "Link this repository to a project first."
            }

        project = db.query(Project).get(repo_record.project_id)
        if not project:
            return {"status": "skipped", "reason": "Linked project not found"}

        # Create scan record
        scan = Scan(
            project_id=project.id,
            status="PENDING",
            scan_source="github",
            github_repo_url=repo_url,
            triggered_by=f"github_webhook:{payload.get('sender', {}).get('login', 'unknown')}"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Audit log
        audit_rec = AuditLog(
            username=f"github_webhook:{payload.get('sender', {}).get('login', 'unknown')}",
            action="scan_triggered",
            details=f"Auto-triggered scan {scan.id} via GitHub push webhook for '{repo_full_name}' (branch: {branch})",
            ip_address=request.client.host if request.client else "unknown"
        )
        db.add(audit_rec)
        db.commit()

        # Parse owner/repo from full_name
        parts = repo_full_name.split("/")
        if len(parts) != 2:
            return {"status": "error", "reason": f"Invalid repo full_name: {repo_full_name}"}
        owner, repo_name = parts

        # Schedule GitHub scan in background
        background_tasks.add_task(
            _run_github_scan_pipeline,
            project.id, scan.id, installation_id, owner, repo_name, branch, db
        )

        return {
            "status": "scan_triggered",
            "scan_id": scan.id,
            "project": project.name,
            "repo": repo_full_name,
            "branch": branch
        }

    # 5. Other events — acknowledge but don't process
    return {"status": "acknowledged", "event": event_type}


# ──────────────────────────── Background Scan Runner ────────────────────────────

def _run_github_scan_pipeline(
    project_id: int, scan_id: int,
    installation_id: str, owner: str, repo: str, branch: str,
    db: Session
):
    """
    Background task: fetch code from GitHub, run the scan pipeline, then cleanup.
    """
    fetcher = CodeFetcher()
    scan_uuid = f"github_{scan_id}_{uuid.uuid4().hex[:8]}"

    try:
        # 1. Get installation token and fetch code
        token = get_installation_token(installation_id)
        code_index = fetcher.fetch_from_github(scan_uuid, token, owner, repo, branch)

        # 2. The fetched code is now on disk — pass the directory to the scan pipeline
        target_dir = os.path.join(fetcher.extraction_base_path, scan_uuid)
        run_scan_pipeline(project_id, scan_id, target_dir, db)

    finally:
        # 3. Cleanup extracted code
        fetcher.cleanup(scan_uuid)
