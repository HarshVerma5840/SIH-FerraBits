import os
import json
import xml.etree.ElementTree as ET
import re

# Supported manifest patterns
MANIFEST_PATTERNS = {
    "javascript": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "python": ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock"],
    "java": ["pom.xml", "build.gradle", "gradle.lockfile"],
    "docker": ["Dockerfile", "docker-compose.yml"]
}

def detect_languages(directory_path):
    """Engine 2: Language Detection Engine"""
    extensions = {
        "JavaScript": [".js", ".jsx", ".ts", ".tsx"],
        "Python": [".py"],
        "Java": [".java", ".jar", ".class"],
        "Docker": ["Dockerfile", "docker-compose.yml"]
    }
    found_languages = set()
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in extensions["JavaScript"] or file in extensions["JavaScript"]:
                found_languages.add("JavaScript")
            if ext in extensions["Python"]:
                found_languages.add("Python")
            if ext in extensions["Java"] or file in extensions["Java"]:
                found_languages.add("Java")
            if file == "Dockerfile" or file == "docker-compose.yml":
                found_languages.add("Docker")
    return list(found_languages)

def detect_ecosystems(manifests):
    """Engine 3: Ecosystem Detection Engine"""
    ecosystems = set()
    for manifest in manifests:
        filename = os.path.basename(manifest)
        if filename in ["package.json", "package-lock.json"]:
            ecosystems.add("npm")
        elif filename in ["requirements.txt", "poetry.lock", "Pipfile.lock"]:
            ecosystems.add("pypi")
        elif filename in ["pom.xml", "build.gradle"]:
            ecosystems.add("maven")
        elif filename in ["Dockerfile", "docker-compose.yml"]:
            ecosystems.add("docker")
    return list(ecosystems)

def discover_manifests(directory_path):
    """Engine 4: Manifest Discovery Engine"""
    discovered = []
    all_patterns = []
    for l in MANIFEST_PATTERNS.values():
        all_patterns.extend(l)
        
    for root, dirs, files in os.walk(directory_path):
        # Ignore common build/cache directories
        if any(x in root for x in ["node_modules", ".git", "__pycache__", "venv", ".venv", "build", "dist"]):
            continue
        for file in files:
            if file in all_patterns or file.endswith(".lock") or file.endswith(".lockfile"):
                filepath = os.path.join(root, file)
                # Convert backslashes for standard UNIX representation in SBOM
                relpath = os.path.relpath(filepath, directory_path).replace("\\", "/")
                discovered.append({
                    "name": file,
                    "filepath": relpath,
                    "fullpath": filepath
                })
    return discovered

def parse_package_json(filepath, relative_path):
    dependencies = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        supplier = data.get("author", {}).get("name") if isinstance(data.get("author"), dict) else data.get("author", "Unknown")
        repo = data.get("repository", {}).get("url") if isinstance(data.get("repository"), dict) else data.get("repository", "Unknown")
        license_str = data.get("license", "Unknown")
        
        # Check direct dependencies
        direct_deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        
        for name, spec in direct_deps.items():
            dependencies.append({
                "name": name,
                "version_spec": spec,
                "ecosystem": "npm",
                "direct": True,
                "depth": 0,
                "type": "library",
                "source_file": relative_path,
                "supplier": supplier,
                "repository": repo,
                "license": license_str
            })
            
        for name, spec in dev_deps.items():
            dependencies.append({
                "name": name,
                "version_spec": spec,
                "ecosystem": "npm",
                "direct": True,
                "depth": 0,
                "type": "library",
                "source_file": relative_path,
                "version_source": "manifest",
                "supplier": supplier,
                "repository": repo,
                "license": license_str
            })
    except Exception as e:
        print(f"Error parsing package.json {filepath}: {str(e)}")
    return dependencies

def _parse_lock_packages(packages, relative_path, dependencies):
    for pkg_path, pkg_info in packages.items():
        if not pkg_path:
            continue
        if "node_modules/" in pkg_path:
            parts = pkg_path.split("node_modules/")
            name = parts[-1]
        else:
            name = pkg_path
            
        version = pkg_info.get("version")
        if version:
            license_str = pkg_info.get("license", "Unknown")
            integrity = pkg_info.get("integrity", "Unknown")
            dependencies.append({
                "name": name,
                "version": version,
                "ecosystem": "npm",
                "direct": False,
                "depth": pkg_path.count("node_modules"),
                "type": "library",
                "source_file": relative_path,
                "hash": integrity,
                "license": license_str,
                "dependencies": list(pkg_info.get("dependencies", {}).keys())
            })

def _parse_lock_dependencies_v1(deps_dict, relative_path, dependencies, depth=1):
    for name, info in deps_dict.items():
        version = info.get("version")
        if version:
            integrity = info.get("integrity", "Unknown")
            dependencies.append({
                "name": name,
                "version": version,
                "ecosystem": "npm",
                "direct": False,
                "depth": depth,
                "type": "library",
                "source_file": relative_path,
                "hash": integrity,
                "dependencies": list(info.get("requires", {}).keys())
            })
        if "dependencies" in info:
            _parse_lock_dependencies_v1(info["dependencies"], relative_path, dependencies, depth + 1)

def parse_package_lock(filepath, relative_path):
    dependencies = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        if "packages" in data:
            for pkg_path, pkg_info in data["packages"].items():
                if not pkg_path: # Root package
                    continue
                # Extract package name from node_modules path
                if "node_modules/" in pkg_path:
                    parts = pkg_path.split("node_modules/")
                    name = parts[-1]
                else:
                    name = pkg_path
                    
                version = pkg_info.get("version")
                if version:
                    license_str = pkg_info.get("license", "Unknown")
                    integrity = pkg_info.get("integrity", "Unknown")
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "direct": False, # Will be resolved by correlation
                        "depth": pkg_path.count("node_modules"),
                        "type": "library",
                        "source_file": relative_path,
                        "version_source": "lockfile",
                        "hash": integrity,
                        "license": license_str,
                        "dependencies": list(pkg_info.get("dependencies", {}).keys())
                    })
        # Legacy npm lock v1
        elif "dependencies" in data:
            def recurse_v1(deps_dict, depth=1):
                for name, info in deps_dict.items():
                    version = info.get("version")
                    if version:
                        integrity = info.get("integrity", "Unknown")
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "npm",
                            "direct": False,
                            "depth": depth,
                            "type": "library",
                            "source_file": relative_path,
                            "version_source": "lockfile",
                            "hash": integrity,
                            "dependencies": list(info.get("requires", {}).keys())
                        })
                    if "dependencies" in info:
                        recurse_v1(info["dependencies"], depth + 1)
            recurse_v1(data["dependencies"])

    except Exception as e:
        print(f"Error parsing package-lock.json {filepath}: {str(e)}")
    return dependencies

def parse_requirements_txt(filepath, relative_path):
    dependencies = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r"):
                continue
            
            # Match package name and version spec
            # Example: requests==2.28.1 or flask>=2.0
            match = re.match(r"^([a-zA-Z0-9_\-\[\]]+)\s*([>=<~!]+)\s*([a-zA-Z0-9_\.\-\*]+)", line)
            if match:
                name = match.group(1)
                spec = match.group(2) + match.group(3)
                version = match.group(3)
                dependencies.append({
                    "name": name.lower(),
                    "version": version,
                    "version_spec": spec,
                    "ecosystem": "pypi",
                    "direct": True,
                    "depth": 0,
                    "type": "library",
                    "source_file": relative_path,
                    "version_source": "manifest"
                })
            else:
                # Name only without strict version spec
                name = re.match(r"^([a-zA-Z0-9_\-\[\]]+)", line)
                if name:
                    dependencies.append({
                        "name": name.group(1).lower(),
                        "version": "UNKNOWN",
                        "version_spec": "*",
                        "ecosystem": "pypi",
                        "direct": True,
                        "depth": 0,
                        "type": "library",
                        "source_file": relative_path,
                        "version_source": "manifest"
                    })
    except Exception as e:
        print(f"Error parsing requirements.txt {filepath}: {str(e)}")
    return dependencies

def parse_pom_xml(filepath, relative_path):
    dependencies = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        # XML namespaces in maven pom
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
            
        deps = root.find(f".//{ns}dependencies")
        if deps is not None:
            for dep in deps.findall(f"{ns}dependency"):
                group_id = dep.find(f"{ns}groupId")
                artifact_id = dep.find(f"{ns}artifactId")
                version = dep.find(f"{ns}version")
                
                group_id_text = group_id.text if group_id is not None else ""
                artifact_id_text = artifact_id.text if artifact_id is not None else ""
                version_text = version.text if version is not None else "UNKNOWN"
                
                # Maven coordinates
                name = f"{group_id_text}:{artifact_id_text}"
                dependencies.append({
                    "name": name,
                    "version": version_text,
                    "ecosystem": "maven",
                    "direct": True,
                    "depth": 0,
                    "type": "library",
                    "source_file": relative_path,
                    "version_source": "manifest"
                })
    except Exception as e:
        print(f"Error parsing pom.xml {filepath}: {str(e)}")
    return dependencies

def parse_dockerfile(filepath, relative_path):
    dependencies = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Match FROM lines
        from_matches = re.findall(r"^\s*FROM\s+([^\s]+)", content, re.MULTILINE | re.IGNORECASE)
        for base_img in from_matches:
            # Example: python:3.9-slim or alpine:latest
            if ":" in base_img:
                name, version = base_img.split(":", 1)
            else:
                name = base_img
                version = "latest"
                
            dependencies.append({
                "name": name,
                "version": version,
                "ecosystem": "docker",
                "direct": True,
                "depth": 0,
                "type": "container",
                "source_file": relative_path,
                "version_source": "manifest"
            })
    except Exception as e:
        print(f"Error parsing Dockerfile {filepath}: {str(e)}")
    return dependencies

def _parse_manifests(manifests, raw_components, npm_package_data, npm_lock_data):
    for mf in manifests:
        filename = mf["name"]
        fullpath = mf["fullpath"]
        relpath = mf["filepath"]
        
        if filename == "package.json":
            npm_package_data.extend(parse_package_json(fullpath, relpath))
        elif filename == "package-lock.json":
            npm_lock_data.extend(parse_package_lock(fullpath, relpath))
        elif filename == "requirements.txt":
            raw_components.extend(parse_requirements_txt(fullpath, relpath))
        elif filename == "pom.xml":
            raw_components.extend(parse_pom_xml(fullpath, relpath))
        elif filename == "Dockerfile":
            raw_components.extend(parse_dockerfile(fullpath, relpath))

def _resolve_npm_dependencies(npm_package_data, npm_lock_data, raw_components):
    if not npm_package_data:
        if npm_lock_data:
            for trans in npm_lock_data:
                trans["direct"] = (trans["depth"] == 1)
                raw_components.append(trans)
        return

    if npm_lock_data:
        lock_map = {item["name"]: item for item in npm_lock_data}
        for direct in npm_package_data:
            name = direct["name"]
            if name in lock_map:
                direct["version"] = lock_map[name]["version"]
                direct["hash"] = lock_map[name].get("hash", "Unknown")
                direct["license"] = lock_map[name].get("license", direct["license"])
                lock_map.pop(name)
            else:
                direct["version"] = direct.get("version_spec", "UNKNOWN")
            raw_components.append(direct)
            
        for name, trans in lock_map.items():
            trans["direct"] = False
            raw_components.append(trans)
    else:
        for direct in npm_package_data:
            direct["version"] = direct.get("version_spec", "UNKNOWN")
            raw_components.append(direct)

def discover_dependencies(manifests):
    """
    Engine 5: Dependency Discovery Engine
    Engine 6: Direct Dependency Engine
    Engine 7: Transitive Dependency Resolution Engine
    Engine 8: Version Resolution Engine
    """
    raw_components = []
    npm_lock_data = []
    npm_package_data = []
    
    _parse_manifests(manifests, raw_components, npm_package_data, npm_lock_data)
    _resolve_npm_dependencies(npm_package_data, npm_lock_data, raw_components)
            
    unique_components = {}
    for comp in raw_components:
        key = f"{comp['ecosystem']}:{comp['name']}@{comp.get('version', 'UNKNOWN')}"
        if key not in unique_components:
            unique_components[key] = comp
            
    return list(unique_components.values())

def run_repository_discovery(directory_path):
    """Engine 1: Repository Discovery Engine"""
    languages = detect_languages(directory_path)
    manifests = discover_manifests(directory_path)
    ecosystems = detect_ecosystems([m["fullpath"] for m in manifests])
    components = discover_dependencies(manifests)
    
    return {
        "project_path": directory_path,
        "languages": languages,
        "ecosystems": ecosystems,
        "manifests": manifests,
        "components": components
    }
