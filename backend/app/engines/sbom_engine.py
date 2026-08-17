import uuid
import json
import hashlib
import os
from datetime import datetime
from urllib.parse import quote
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Dynamic Key Pair Generation for SBOM Signing Demo
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()

def generate_purl(ecosystem, name, version):
    """Engine 10: PURL Generation Engine"""
    eco_map = {
        "npm": "npm",
        "pypi": "pypi",
        "maven": "maven",
        "docker": "docker"
    }
    eco = eco_map.get(ecosystem.lower(), "generic")
    
    # Handle namespace for maven (group_id:artifact_id)
    if eco == "maven" and ":" in name:
        group_id, artifact_id = name.split(":", 1)
        purl = f"pkg:maven/{quote(group_id)}/{quote(artifact_id)}@{quote(version)}"
    elif eco == "npm" and name.startswith("@"):
        # Scoped npm packages, e.g. @types/node -> pkg:npm/%40types/node@14.0.0
        parts = name.split("/")
        namespace = parts[0]
        pkg_name = "/".join(parts[1:])
        purl = f"pkg:npm/{quote(namespace)}/{quote(pkg_name)}@{quote(version)}"
    else:
        purl = f"pkg:{eco}/{quote(name)}@{quote(version)}"
        
    return purl

def generate_cyclonedx(project_name, components, dependencies_relations=None):
    """Engine 11: SBOM Generation Engine (CycloneDX)"""
    bom_uuid = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    cdx_components = []
    for c in components:
        purl = c.get("purl") or generate_purl(c["ecosystem"], c["name"], c.get("version", "UNKNOWN"))
        
        comp_obj = {
            "type": c.get("type", "library"),
            "name": c["name"],
            "version": c.get("version", "UNKNOWN"),
            "purl": purl,
            "bom-ref": purl
        }
        
        if c.get("supplier"):
            comp_obj["supplier"] = {"name": c["supplier"]}
        if c.get("license"):
            comp_obj["licenses"] = [{"license": {"id": c["license"]}}]
        if c.get("hash"):
            # Format hash (e.g. SHA-256, SHA-1, MD5)
            comp_obj["hashes"] = [{"alg": "SHA-256", "content": c["hash"]}]
            
        cdx_components.append(comp_obj)
        
    # Standard dependencies structure
    cdx_dependencies = []
    if dependencies_relations:
        for parent, children in dependencies_relations.items():
            cdx_dependencies.append({
                "ref": parent,
                "dependsOn": children
            })
            
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": bom_uuid,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Antigravity Security",
                    "name": "SBOMGuard",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": "1.0.0"
            }
        },
        "components": cdx_components,
        "dependencies": cdx_dependencies
    }
    
    return sbom

def generate_spdx(project_name, components):
    """Engine 11: SBOM Generation Engine (SPDX)"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    spdx_id = f"SPDXRef-DOCUMENT"
    
    spdx_packages = []
    for i, c in enumerate(components):
        pkg_ref = f"SPDXRef-Package-{i}"
        purl = c.get("purl") or generate_purl(c["ecosystem"], c["name"], c.get("version", "UNKNOWN"))
        
        pkg_obj = {
            "name": c["name"],
            "SPDXID": pkg_ref,
            "versionInfo": c.get("version", "UNKNOWN"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseDeclared": c.get("license", "NOASSERTION"),
            "licenseConcluded": c.get("license", "NOASSERTION"),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl
                }
            ]
        }
        spdx_packages.append(pkg_obj)
        
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": spdx_id,
        "name": project_name,
        "documentNamespace": f"https://sbomguard.io/spdx/{project_name}-{uuid.uuid4()}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: SBOMGuard-1.0.0"]
        },
        "packages": spdx_packages
    }
    
    return sbom

def normalize_sbom(sbom_dict):
    """Engine 12: SBOM Normalization Engine"""
    # Ensures all fields align with our standardized representation
    normalized = []
    if "components" in sbom_dict:
        for c in sbom_dict["components"]:
            licenses = []
            if "licenses" in c:
                for lic in c["licenses"]:
                    if "license" in lic:
                        licenses.append(lic["license"].get("id") or lic["license"].get("name"))
            license_str = licenses[0] if licenses else "Unknown"
            
            hash_str = "Unknown"
            if "hashes" in c and c["hashes"]:
                hash_str = c["hashes"][0].get("content")
                
            normalized.append({
                "name": c.get("name"),
                "version": c.get("version", "UNKNOWN"),
                "purl": c.get("purl"),
                "ecosystem": c.get("purl", "").split(":")[1].split("/")[0] if ":" in c.get("purl", "") else "Unknown",
                "supplier": c.get("supplier", {}).get("name", "Unknown") if isinstance(c.get("supplier"), dict) else "Unknown",
                "license": license_str,
                "hash": hash_str,
                "type": c.get("type", "library")
            })
    return normalized

def validate_sbom(sbom_dict):
    """Engine 13: SBOM Validation Engine"""
    errors = []
    if not isinstance(sbom_dict, dict):
        return False, ["SBOM is not a valid JSON object"]
        
    is_cyclonedx = sbom_dict.get("bomFormat") == "CycloneDX"
    is_spdx = "spdxVersion" in sbom_dict
    
    if not is_cyclonedx and not is_spdx:
        return False, ["Unrecognized SBOM format. Must be CycloneDX or SPDX"]
        
    if is_cyclonedx:
        if not sbom_dict.get("specVersion"):
            errors.append("Missing 'specVersion'")
        if not sbom_dict.get("serialNumber"):
            errors.append("Missing 'serialNumber'")
        if "components" in sbom_dict:
            for i, comp in enumerate(sbom_dict["components"]):
                if not comp.get("name"):
                    errors.append(f"Component at index {i} is missing 'name'")
                if not comp.get("version"):
                    errors.append(f"Component '{comp.get('name', i)}' is missing 'version'")
                if not comp.get("purl"):
                    errors.append(f"Component '{comp.get('name', i)}' is missing 'purl'")
    elif is_spdx:
        if not sbom_dict.get("name"):
            errors.append("Missing SPDX document 'name'")
        if not sbom_dict.get("documentNamespace"):
            errors.append("Missing SPDX 'documentNamespace'")
            
    return len(errors) == 0, errors

def calculate_quality_score(components):
    """Engine 14: SBOM Quality / Completeness Engine"""
    if not components:
        return {"score": 0, "metrics": {}, "explanations": ["No components scanned"]}
        
    n = len(components)
    version_count = 0
    purl_count = 0
    license_count = 0
    supplier_count = 0
    hash_count = 0
    dependency_count = 0 # tracking direct/transitive relationships
    
    explanations = []
    for c in components:
        name = c["name"]
        
        # 1. Version Coverage
        if c.get("version") and c["version"] != "UNKNOWN":
            version_count += 1
        else:
            explanations.append(f"Component '{name}' is missing an exact version")
            
        # 2. PURL Coverage
        if c.get("purl") and c["purl"].startswith("pkg:"):
            purl_count += 1
        else:
            explanations.append(f"Component '{name}' is missing a Package URL (PURL)")
            
        # 3. License Coverage
        if c.get("license") and c["license"] != "Unknown" and c["license"] != "NOASSERTION":
            license_count += 1
        else:
            explanations.append(f"Component '{name}' is missing declared license metadata")
            
        # 4. Supplier Coverage
        if c.get("supplier") and c["supplier"] != "Unknown":
            supplier_count += 1
        else:
            explanations.append(f"Component '{name}' is missing supplier/publisher info")
            
        # 5. Hash Coverage
        if c.get("hash") and c["hash"] != "Unknown":
            hash_count += 1
        else:
            explanations.append(f"Component '{name}' is missing cryptographic hash")
            
        # 6. Dependency Coverage (depth and direct flag)
        if "direct" in c:
            dependency_count += 1
            
    metrics = {
        "version_coverage": (version_count / n) * 100,
        "purl_coverage": (purl_count / n) * 100,
        "license_coverage": (license_count / n) * 100,
        "supplier_coverage": (supplier_count / n) * 100,
        "hash_coverage": (hash_count / n) * 100,
        "dependency_coverage": (dependency_count / n) * 100
    }
    
    # Heuristic score calculation
    score = (
        metrics["version_coverage"] * 0.25 +
        metrics["purl_coverage"] * 0.20 +
        metrics["license_coverage"] * 0.15 +
        metrics["supplier_coverage"] * 0.15 +
        metrics["hash_coverage"] * 0.15 +
        metrics["dependency_coverage"] * 0.10
    )
    
    return {
        "score": round(score),
        "metrics": metrics,
        "explanations": explanations
    }

def generate_evidence(component):
    """Engine 15: Component Provenance / Evidence Engine"""
    filepath = component.get("source_file", "Unknown")
    ext = os.path.splitext(filepath)[1]
    
    evidence_type = "loose_file"
    confidence = 0.50
    
    if ext == ".lock" or "lock" in filepath:
        evidence_type = "lockfile"
        confidence = 0.99
    elif filepath in ["package.json", "pom.xml", "requirements.txt"]:
        evidence_type = "manifest"
        confidence = 0.90
    elif component.get("supplier") and component.get("hash"):
        evidence_type = "registry_metadata"
        confidence = 0.95
        
    return {
        "filepath": filepath,
        "evidence_type": evidence_type,
        "confidence_score": confidence
    }

def detect_drift(component, latest_versions_db):
    """Engine 16: Dependency Drift Detection Engine"""
    current_version = component.get("version")
    name = component.get("name")
    ecosystem = component.get("ecosystem")
    
    db_key = f"{ecosystem}:{name}"
    latest_version = latest_versions_db.get(db_key, current_version)
    
    if current_version == "UNKNOWN" or latest_version == current_version:
        return {"drift": False, "latest_version": latest_version, "drift_type": "none"}
        
    # Analyze drift type
    curr_parts = current_version.split(".")
    lat_parts = latest_version.split(".")
    
    drift_type = "patch"
    if len(curr_parts) >= 2 and len(lat_parts) >= 2:
        if curr_parts[0] != lat_parts[0]:
            drift_type = "major"
        elif curr_parts[1] != lat_parts[1]:
            drift_type = "minor"
            
    return {
        "drift": True,
        "current_version": current_version,
        "latest_version": latest_version,
        "drift_type": drift_type
    }

def sign_sbom(sbom_dict):
    """Engine 29: SBOM Signing Engine"""
    raw_json = json.dumps(sbom_dict, sort_keys=True)
    digest = hashlib.sha256(raw_json.encode("utf-8")).digest()
    
    signature = PRIVATE_KEY.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Store hex signature in return
    return signature.hex()

def verify_sbom_signature(sbom_dict, signature_hex):
    """Engine 29: SBOM Verification Engine"""
    try:
        raw_json = json.dumps(sbom_dict, sort_keys=True)
        digest = hashlib.sha256(raw_json.encode("utf-8")).digest()
        signature = bytes.fromhex(signature_hex)
        
        PUBLIC_KEY.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "VALID"
    except Exception as e:
        print(f"Signature verification failure: {str(e)}")
        return "INTEGRITY_FAILURE"
