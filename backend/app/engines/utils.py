"""
Shared utility functions used across multiple SBOMGuard AI engines.
Centralises parse_semver and generate_purl which were previously duplicated
in both ai_engine.py and security_engine.py / sbom_engine.py.
"""
import re


def parse_semver(v_str: str) -> list[int]:
    """
    Basic semver extractor. Returns [major, minor, patch] as ints.
    Handles leading 'v', pre-release suffixes, and numeric-only strings.
    """
    v_str = v_str.lstrip("v")
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", v_str)
    if match:
        return [int(match.group(1)), int(match.group(2)), int(match.group(3))]
    numbers = [int(s) for s in re.findall(r"\d+", v_str)]
    while len(numbers) < 3:
        numbers.append(0)
    return numbers[:3]


def generate_purl(ecosystem: str, name: str, version: str) -> str:
    """
    Generate a Package URL (purl) string.
    Format: pkg:<ecosystem>/<name>@<version>
    """
    eco = ecosystem.lower()
    return f"pkg:{eco}/{name}@{version}"
