import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.models.database import engine, Base, SessionLocal, Role, User, Policy, Project
from backend.app.core.security import get_password_hash
from backend.app.api import auth, projects, scans, vulnerabilities, policies, tickets, reports, audit

# Initialize database schema tables
Base.metadata.create_all(bind=engine)

# Seed initial system configuration
def seed_database():
    db = SessionLocal()
    try:
        # 1. Seed Roles
        admin_role = db.query(Role).filter_by(name="ADMIN").first()
        if not admin_role:
            admin_role = Role(name="ADMIN", permissions="*")
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)
            
        analyst_role = db.query(Role).filter_by(name="SECURITY_ANALYST").first()
        if not analyst_role:
            analyst_role = Role(name="SECURITY_ANALYST", permissions="view_dashboard,run_scan,view_policies,accept_risk,view_audit_logs,manage_tickets")
            db.add(analyst_role)
            db.commit()
            
        # 2. Seed Users
        admin_user = db.query(User).filter_by(username="admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@sbomguard.io",
                password_hash=get_password_hash("admin123"),
                role_id=admin_role.id
            )
            db.add(admin_user)
            db.commit()
            
        # 3. Seed Default Policies
        cvss_policy = db.query(Policy).filter_by(rule_type="CVSS_THRESHOLD", action="BLOCK").first()
        if not cvss_policy:
            defaults = [
                Policy(name="Block Critical CVSS", rule_type="CVSS_THRESHOLD", rule_condition=">= 9.0", action="BLOCK", is_active=True),
                Policy(name="Review High CVSS", rule_type="CVSS_THRESHOLD", rule_condition=">= 7.0", action="REVIEW", is_active=True),
                Policy(name="Review AI Anomalies", rule_type="AI_ANOMALY", rule_condition=">= 80", action="REVIEW", is_active=True),
                Policy(name="Block Copyleft Licenses", rule_type="FORBIDDEN_LICENSE", rule_condition="FORBIDDEN", action="BLOCK", is_active=True),
                Policy(name="Review Unknown Versions", rule_type="UNKNOWN_VERSION", rule_condition="UNKNOWN", action="REVIEW", is_active=True)
            ]
            db.add_all(defaults)
            db.commit()
            
        # 4. Seed Demo Project
        demo_project = db.query(Project).filter_by(name="E-Commerce Microservice Hub").first()
        if not demo_project:
            demo_project = Project(
                name="E-Commerce Microservice Hub",
                description="Production retail server containing web manifests, dockerfiles, and python worker scripts."
            )
            db.add(demo_project)
            db.commit()
            
        print("Database seed actions completed successfully.")
    except Exception as e:
        print(f"Error seeding database: {str(e)}")
    finally:
        db.close()

seed_database()

app = FastAPI(
    title="SBOMGuard AI API",
    description="Enterprise AI-powered SBOM and Software Supply Chain Security Platform.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API endpoints
app.include_router(auth.router, prefix="/api")
app.include_router(projects.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(vulnerabilities.router, prefix="/api")
app.include_router(policies.router, prefix="/api")
app.include_router(tickets.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(audit.router, prefix="/api")

@app.get("/")
def read_root():
    return {
        "status": "HEALTHY",
        "service": "SBOMGuard AI Backend Core",
        "engines": 58,
        "mode": "DEMO_PRODUCTION"
    }
