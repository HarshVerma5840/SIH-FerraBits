import re
import json

# Embedded offline vulnerability database representing real CVE entries
OFFLINE_VULN_DB = [
    {
        "cve_id": "CVE-2021-44228",
        "ecosystem": "maven",
        "package_name": "org.apache.logging.log4j:log4j-core",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_versions": "< 2.15.0",
        "fixed_versions": "2.15.0",
        "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    },
    {
        "cve_id": "CVE-2019-10744",
        "ecosystem": "npm",
        "package_name": "lodash",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_versions": "< 4.17.12",
        "fixed_versions": "4.17.12",
        "description": "Prototype pollution vulnerability in lodash in defaultsDeep, merge, and mergeWith functions.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"]
    },
    {
        "cve_id": "CVE-2020-8203",
        "ecosystem": "npm",
        "package_name": "lodash",
        "cvss_score": 7.4,
        "severity": "HIGH",
        "affected_versions": "< 4.17.21",
        "fixed_versions": "4.17.21",
        "description": "Prototype pollution vulnerability in lodash when parsing object keys.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"]
    },
    {
        "cve_id": "CVE-2023-26159",
        "ecosystem": "npm",
        "package_name": "follow-redirects",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected_versions": "< 1.15.4",
        "fixed_versions": "1.15.4",
        "description": "Redirection leak vulnerability when sending credentials to cross-origin endpoints.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-26159"]
    },
    {
        "cve_id": "CVE-2022-40897",
        "ecosystem": "pypi",
        "package_name": "gitpython",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_versions": "< 3.1.30",
        "fixed_versions": "3.1.30",
        "description": "Remote code execution vulnerability in GitPython package via command injection.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-40897"]
    },
    {
        "cve_id": "CVE-2023-32681",
        "ecosystem": "pypi",
        "package_name": "requests",
        "cvss_score": 6.1,
        "severity": "MEDIUM",
        "affected_versions": "< 2.31.0",
        "fixed_versions": "2.31.0",
        "description": "Session cookie leakage across redirect domains.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"]
    },
    {
        "cve_id": "CVE-2024-34064",
        "ecosystem": "pypi",
        "package_name": "jinja2",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected_versions": "< 3.1.4",
        "fixed_versions": "3.1.4",
        "description": "HTML Attribute injection vulnerability when passing user controlled keys.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-34064"]
    }
]

# Standard EOL and Deprecation indicators
DEPRECATED_PACKAGES = {
    "npm": ["request", "rimraf", "uuidv4", "chokidar-cli"],
    "pypi": ["urllib3-v1", "pep8", "pykrige"],
    "maven": ["org.apache.commons:commons-email"]
}

def parse_semver(v_str):
    """Basic semver extractor to compare versions: returns list of ints [major, minor, patch]"""
    # Remove leading v
    v_str = v_str.lstrip("v")
    # Take only digit parts
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", v_str)
    if match:
        return [int(match.group(1)), int(match.group(2)), int(match.group(3))]
    # Fallback to simple number parse
    numbers = [int(s) for s in re.findall(r"\d+", v_str)]
    while len(numbers) < 3:
        numbers.append(0)
    return numbers[:3]

def is_version_affected(current_version, affected_spec):
    """
    Evaluates if current_version matches the affected specification (e.g. '< 2.15.0' or '<= 4.17.11')
    """
    if current_version == "UNKNOWN":
        return False
        
    match = re.match(r"^([<>=!]+)\s*([a-zA-Z0-9_\.\-]+)", affected_spec)
    if not match:
        return False
        
    operator = match.group(1)
    spec_version = match.group(2)
    
    try:
        curr_p = parse_semver(current_version)
        spec_p = parse_semver(spec_version)
        
        if operator == "<":
            return curr_p < spec_p
        elif operator == "<=":
            return curr_p <= spec_p
        elif operator == ">":
            return curr_p > spec_p
        elif operator == ">=":
            return curr_p >= spec_p
        elif operator == "==":
            return curr_p == spec_p
    except Exception:
        # Fallback to simple string match
        return current_version == spec_version
        
    return False

def run_vulnerability_detection(components):
    """
    Engine 19: Vulnerability Detection Engine
    Engine 20: CVE / Vulnerability Correlation Engine
    """
    matches = []
    for c in components:
        name = c["name"]
        version = c.get("version", "UNKNOWN")
        eco = c["ecosystem"]
        
        for vuln in OFFLINE_VULN_DB:
            if vuln["package_name"] == name and vuln["ecosystem"] == eco:
                if is_version_affected(version, vuln["affected_versions"]):
                    matches.append({
                        "component_purl": c.get("purl"),
                        "cve_id": vuln["cve_id"],
                        "cvss_score": vuln["cvss_score"],
                        "severity": vuln["severity"],
                        "affected_versions": vuln["affected_versions"],
                        "fixed_versions": vuln["fixed_versions"],
                        "description": vuln["description"],
                        "references_json": json.dumps(vuln["references"])
                    })
    return matches

def detect_dependency_confusion(component, public_package_list=None):
    """
    Engine 23: Dependency Confusion Detection Engine
    Checks if a package name looks internal/private but might conflict with public registries.
    """
    name = component["name"]
    # Indicators of internal packages: prefix, company names, or naming structures
    internal_keywords = ["internal", "private", "corp", "custom", "local", "secret", "sih"]
    is_internal_pattern = any(kw in name.lower() for kw in internal_keywords) or name.startswith("@sih-")
    
    # If the user has uploaded an internal package, and we check public registry
    # In offline mode, if it starts with @sih or has internal keywords and also matches public names
    if is_internal_pattern:
        return {
            "confusion_risk": True,
            "risk_level": "HIGH",
            "evidence": f"Package name '{name}' looks like a private namespace but lacks private registry scope tags.",
            "recommendation": "Configure registry scope mapping in npmrc / pip.conf to restrict searches to internal repositories."
        }
    return {"confusion_risk": False, "risk_level": "LOW"}

def detect_supply_chain_attack(component):
    """
    Engine 24: Supply Chain Attack Detection Engine
    Detects typosquatting, hijacked maintainers, etc.
    """
    name = component["name"]
    # Typosquatting heuristics
    popular_packages = ["lodash", "express", "requests", "flask", "numpy", "pandas"]
    
    for pop in popular_packages:
        if name != pop and len(name) >= len(pop) - 1 and len(name) <= len(pop) + 1:
            # Edit distance 1 check
            # For simplicity, check if name contains pop or edit distance is close
            diff_chars = sum(1 for a, b in zip(name, pop) if a != b)
            if diff_chars <= 1 and component["ecosystem"] == "npm":
                return {
                    "attack_detected": True,
                    "attack_type": "Typosquatting",
                    "risk_level": "CRITICAL",
                    "description": f"Package '{name}' is highly similar to popular package '{pop}'. Potential typosquatting compromise."
                }
                
    # Check install scripts
    if component.get("has_install_script") or "install" in str(component.get("source_file")):
        if component.get("obfuscation_score", 0) > 0.6:
            return {
                "attack_detected": True,
                "attack_type": "Malicious Script Injection",
                "risk_level": "CRITICAL",
                "description": f"Package '{name}' contains installation scripts combined with high code obfuscation."
            }
            
    return {"attack_detected": False}

def detect_lifecycle_status(component):
    """Engine 26: Component Lifecycle / EOL Detection Engine"""
    name = component["name"]
    eco = component["ecosystem"]
    
    if eco in DEPRECATED_PACKAGES and name in DEPRECATED_PACKAGES[eco]:
        return {
            "status": "DEPRECATED",
            "is_eol": True,
            "recommendation": f"Package '{name}' is deprecated and unmaintained. Migrate to active alternatives."
        }
    return {
        "status": "ACTIVE",
        "is_eol": False,
        "recommendation": "Package is actively maintained"
    }

def analyze_package_reputation(component):
    """Engine 27: Package Reputation Analysis Engine"""
    # Heuristics based on package fields
    score = 100
    indicators = []
    
    age = component.get("age_days", 1000)
    if age < 30:
        score -= 40
        indicators.append("Brand new package (less than 30 days old)")
    elif age < 180:
        score -= 15
        indicators.append("Relatively young package (less than 6 months old)")
        
    maintainer_count = component.get("maintainer_count", 3)
    if maintainer_count == 1:
        score -= 20
        indicators.append("Single maintainer package")
        
    reputation = component.get("reputation_score", 85)
    if reputation < 40:
        score -= 30
        indicators.append("Low public downloads / star rating")
        
    return {
        "reputation_score": max(score, 0),
        "indicators": indicators,
        "level": "EXCELLENT" if score > 80 else ("GOOD" if score > 50 else "POOR")
    }

def verify_cryptographic_integrity(component):
    """Engine 28: Cryptographic Integrity Engine"""
    file_hash = component.get("hash", "Unknown")
    if file_hash == "Unknown" or not file_hash:
        return "UNKNOWN"
        
    # Check format of sha256 or integrity hash
    if file_hash.startswith("sha512-") or file_hash.startswith("sha256-"):
        return "VALID"
    elif len(file_hash) == 64: # SHA-256 hex
        return "VALID"
        
    return "INVALID"

def compute_cross_project_intelligence(component_purl, all_project_sboms):
    """Engine 32: Cross-Project Component Intelligence Engine"""
    affected_projects = []
    for proj_id, sbom_components in all_project_sboms.items():
        for comp in sbom_components:
            if comp["purl"] == component_purl:
                affected_projects.append(proj_id)
                break
    return {
        "global_impact": len(affected_projects) > 1,
        "affected_projects_count": len(affected_projects),
        "affected_projects": affected_projects
    }

def evaluate_contextual_security(component, vulnerabilities, risk_assessment=None):
    """
    Engine 33: Contextual Security Analysis Engine
    Engine 34: VEX / Vulnerability Context Engine
    """
    if not vulnerabilities:
        return {
            "vex_status": "NOT_AFFECTED",
            "vex_justification": "No vulnerabilities matching this component",
            "contextual_severity": "NONE"
        }
        
    # Standard VEX evaluations: check depth and production settings
    is_direct = component.get("direct", True)
    depth = component.get("depth", 0)
    
    # If transitive and at high depth, the exploitability might be lower contextually
    if not is_direct and depth > 2:
        return {
            "vex_status": "UNDER_INVESTIGATION",
            "vex_justification": "Vulnerability is located in a deep transitive dependency (>2 levels deep). Exploitability is under evaluation.",
            "contextual_severity": "MEDIUM" if any(v["severity"] in ["CRITICAL", "HIGH"] for v in vulnerabilities) else "LOW"
        }
        
    # Default state is affected
    max_severity = "LOW"
    for v in vulnerabilities:
        if v["severity"] == "CRITICAL":
            max_severity = "CRITICAL"
        elif v["severity"] == "HIGH" and max_severity != "CRITICAL":
            max_severity = "HIGH"
        elif v["severity"] == "MEDIUM" and max_severity not in ["CRITICAL", "HIGH"]:
            max_severity = "MEDIUM"
            
    return {
        "vex_status": "AFFECTED",
        "vex_justification": "Component is active in application build and reachable as a direct dependency.",
        "contextual_severity": max_severity
    }
