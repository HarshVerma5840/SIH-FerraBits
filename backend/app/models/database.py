import os
from datetime import datetime, timezone

def get_utc_now():
    return datetime.now(timezone.utc)
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey, Table
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

# Database URL configuration with SQLite fallback
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sbom_security.db")

# Adjust for pg8000 dialect if using postgresql
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://")

# Connect args for SQLite compatibility
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Many-to-Many relationship table for Component Vulnerability Map
component_vulnerabilities = Table(
    "component_vulnerabilities_map",
    Base.metadata,
    Column("component_id", Integer, ForeignKey("sbom_components.id", ondelete="CASCADE"), primary_key=True),
    Column("vulnerability_id", Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True),
)

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True) # ADMIN, SECURITY_ANALYST, DEVELOPER, VIEWER
    permissions = Column(Text, nullable=True) # JSON or comma-separated actions
    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=True)
    password_hash = Column(String(200), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"))
    created_at = Column(DateTime, default=get_utc_now)
    
    role = relationship("Role", back_populates="users")

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)
    
    repositories = relationship("Repository", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    sbom_versions = relationship("SBOMVersion", back_populates="project", cascade="all, delete-orphan")
    sbom_diffs = relationship("SBOMDiff", back_populates="project", cascade="all, delete-orphan")
    tickets = relationship("Ticket", back_populates="project", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="project", cascade="all, delete-orphan")

class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    url = Column(String(500), nullable=False)
    branch = Column(String(100), default="main")
    credentials = Column(String(200), nullable=True) # optional token/pass
    last_scanned_at = Column(DateTime, nullable=True)
    
    project = relationship("Project", back_populates="repositories")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(50), default="PENDING") # PENDING, RUNNING, COMPLETED, FAILED
    triggered_by = Column(String(100), default="system")
    started_at = Column(DateTime, default=get_utc_now)
    created_at = Column(DateTime, default=get_utc_now)
    completed_at = Column(DateTime, nullable=True)
    log = Column(Text, nullable=True)
    
    project = relationship("Project", back_populates="scans")
    sboms = relationship("SBOM", back_populates="scan", cascade="all, delete-orphan")
    anomalies = relationship("Anomaly", back_populates="scan", cascade="all, delete-orphan")
    risk_assessments = relationship("RiskAssessment", back_populates="scan", cascade="all, delete-orphan")
    remediations = relationship("RemediationRecommendation", back_populates="scan", cascade="all, delete-orphan")
    ml_predictions = relationship("MLPrediction", back_populates="scan", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="scan", cascade="all, delete-orphan")

class SBOM(Base):
    __tablename__ = "sboms"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    format = Column(String(50), default="CycloneDX") # CycloneDX, SPDX
    version = Column(String(50), default="1.4")
    generated_at = Column(DateTime, default=get_utc_now)
    raw_json = Column(Text, nullable=False) # raw generated CycloneDX JSON
    file_hash = Column(String(64), nullable=False) # SHA-256 integrity hash
    signature = Column(Text, nullable=True) # digital signature
    verification_status = Column(String(50), default="UNKNOWN") # VALID, INVALID, UNSIGNED
    
    scan = relationship("Scan", back_populates="sboms")
    components = relationship("SBOMComponent", back_populates="sbom", cascade="all, delete-orphan")

class SBOMComponent(Base):
    __tablename__ = "sbom_components"
    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False, index=True)
    version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), nullable=False, index=True) # npm, pypi, maven, docker
    purl = Column(String(500), nullable=False, index=True)
    supplier = Column(String(200), nullable=True)
    repository = Column(String(500), nullable=True)
    license = Column(String(100), nullable=True)
    hash_sha256 = Column(String(64), nullable=True)
    component_type = Column(String(50), default="library") # library, application, container
    depth = Column(Integer, default=0) # direct=0, transitive>0
    direct = Column(Boolean, default=True)
    source_file = Column(String(500), nullable=True) # manifest source
    confidence = Column(Float, default=1.0) # confidence level of identification (0.0 - 1.0)
    
    sbom = relationship("SBOM", back_populates="components")
    evidence = relationship("Evidence", back_populates="component", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", secondary=component_vulnerabilities, back_populates="components")

class Dependency(Base):
    __tablename__ = "dependencies"
    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False)
    component_purl = Column(String(500), nullable=False, index=True)
    dependent_purl = Column(String(500), nullable=False, index=True) # purl of component depending on it
    relationship_type = Column(String(50), default="depends-on")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(50), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    affected_versions = Column(Text, nullable=True) # JSON or semicolon separated string
    fixed_versions = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    references_json = Column(Text, nullable=True) # serialized list of URLs
    
    components = relationship("SBOMComponent", secondary=component_vulnerabilities, back_populates="vulnerabilities")

class Anomaly(Base):
    __tablename__ = "anomalies"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    component_purl = Column(String(500), nullable=False, index=True)
    anomaly_score = Column(Float, nullable=False) # Isolation Forest score
    anomaly_probability = Column(Float, nullable=False)
    classification = Column(String(50), nullable=False) # NORMAL, SUSPICIOUS, ANOMALOUS
    indicators_json = Column(Text, nullable=True) # contributing features reasons
    
    scan = relationship("Scan", back_populates="anomalies")

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    component_purl = Column(String(500), nullable=False, index=True)
    risk_score = Column(Float, nullable=False) # 0-100 score
    risk_level = Column(String(50), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    explanation = Column(Text, nullable=True)
    blast_radius_json = Column(Text, nullable=True) # downstream impact paths
    production_exposure = Column(Boolean, default=False)
    
    scan = relationship("Scan", back_populates="risk_assessments")

class License(Base):
    __tablename__ = "licenses"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    classification = Column(String(50), default="PERMISSIVE") # PERMISSIVE, RESTRICTED, FORBIDDEN
    description = Column(Text, nullable=True)

class Policy(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    rule_type = Column(String(100), nullable=False) # e.g. CVSS_THRESHOLD, FORBIDDEN_LICENSE, ANOMALY_SCORE
    rule_condition = Column(String(200), nullable=False) # e.g. >= 9.0, GPL-3.0, >= 80
    action = Column(String(50), default="REVIEW") # BLOCK, REVIEW, PASS
    is_active = Column(Boolean, default=True)

class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(String(50), unique=True, nullable=False, index=True) # e.g. SEC-001
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    component_name = Column(String(200), nullable=False)
    component_version = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    risk_score = Column(Float, nullable=False)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    assignee = Column(String(100), nullable=True)
    status = Column(String(50), default="OPEN") # OPEN, IN_PROGRESS, RESOLVED
    created_date = Column(DateTime, default=get_utc_now)
    
    project = relationship("Project", back_populates="tickets")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    component_purl = Column(String(500), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    reason = Column(Text, nullable=False)
    policy_action = Column(String(50), nullable=False) # BLOCK, REVIEW
    created_at = Column(DateTime, default=get_utc_now)
    is_resolved = Column(Boolean, default=False)
    
    project = relationship("Project", back_populates="alerts")
    scan = relationship("Scan", back_populates="alerts")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, index=True)
    action = Column(String(100), nullable=False) # login, scan, policy_change, etc.
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=get_utc_now)
    ip_address = Column(String(50), nullable=True)

class SBOMVersion(Base):
    __tablename__ = "sbom_versions"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    version_number = Column(Integer, nullable=False)
    sbom_id = Column(Integer, ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=get_utc_now)
    
    project = relationship("Project", back_populates="sbom_versions")

class SBOMDiff(Base):
    __tablename__ = "sbom_diffs"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    base_scan_id = Column(Integer, nullable=False)
    head_scan_id = Column(Integer, nullable=False)
    added_json = Column(Text, nullable=True) # JSON list of components added
    removed_json = Column(Text, nullable=True) # JSON list of components removed
    updated_json = Column(Text, nullable=True) # JSON list of components updated
    created_at = Column(DateTime, default=get_utc_now)
    
    project = relationship("Project", back_populates="sbom_diffs")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("sbom_components.id", ondelete="CASCADE"), nullable=False)
    filepath = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=True)
    evidence_type = Column(String(100), nullable=False) # manifest, lockfile, registry_metadata
    confidence_score = Column(Float, default=1.0)
    
    component = relationship("SBOMComponent", back_populates="evidence")

class RemediationRecommendation(Base):
    __tablename__ = "remediation_recommendations"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    component_purl = Column(String(500), nullable=False, index=True)
    current_version = Column(String(100), nullable=False)
    recommended_version = Column(String(100), nullable=True)
    upgrade_impact = Column(Text, nullable=True) # downstream dependents impacted description
    remediation_type = Column(String(100), default="upgrade") # upgrade, patch, alternate
    
    scan = relationship("Scan", back_populates="remediations")

class MLPrediction(Base):
    __tablename__ = "ml_predictions"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    component_purl = Column(String(500), nullable=False, index=True)
    prediction_type = Column(String(50), nullable=False) # anomaly, malicious
    features_json = Column(Text, nullable=False)
    prediction_output_json = Column(Text, nullable=False)
    confidence_score = Column(Float, default=1.0)
    
    scan = relationship("Scan", back_populates="ml_predictions")

def init_db():
    Base.metadata.create_all(bind=engine)
