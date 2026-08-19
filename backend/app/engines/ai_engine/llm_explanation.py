"""
LLM Explanation Service — ai_engine/llm_explanation.py

Responsibility:
  Convert a VERIFIED, structured security finding into a concise, developer-friendly
  explanation and remediation guidance using Google Gemini.

Strict boundaries:
  - This service NEVER determines vulnerability status.
  - It NEVER invents CVE IDs, CVSS scores, affected/fixed versions, or dependency counts.
  - All security facts come from the caller (verified OSV/security_engine output).
  - When Gemini is unavailable or key is missing, returns a deterministic fallback.
  - API key is read from environment only — never hardcoded.
"""

import os
import json
import time
import hashlib
import threading
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Simple in-memory cache  { cache_key: (timestamp, explanation_dict) }
# ─────────────────────────────────────────────────────────────────────────────
_explanation_cache: dict = {}
_cache_lock = threading.Lock()
CACHE_TTL_SECONDS = 3600  # 1 hour — explanations don't change while vuln data is unchanged

# ─────────────────────────────────────────────────────────────────────────────
# Gemini model config
# ─────────────────────────────────────────────────────────────────────────────
_GEMINI_MODEL = "gemini-1.5-flash-8b"  # Cheapest, fast enough for single-finding explanations
_GEMINI_TIMEOUT = 15  # seconds

SYSTEM_INSTRUCTION = (
    "You are a cybersecurity developer-assistance layer embedded in an SBOM security tool. "
    "Your only role is to explain the verified vulnerability facts provided to you in structured form, "
    "and give concise, technically accurate developer remediation guidance. "
    "Rules you must never break:\n"
    "- Never invent, modify, or guess CVE IDs, CVSS scores, affected versions, fixed versions, "
    "exploit status, or dependency counts not present in the input.\n"
    "- If a field is missing or null, explicitly state it is unavailable — do not guess.\n"
    "- Do not claim a fix exists unless fixed_versions is non-empty in the input.\n"
    "- Be concise. Developers need clear actionable guidance, not lengthy prose.\n"
    "- Respond ONLY with a valid JSON object matching the requested schema."
)

RESPONSE_SCHEMA = {
    "summary": "string — 1-2 sentence plain-language explanation of the vulnerability",
    "why_it_matters": "string — why this specific finding deserves attention in this component",
    "technical_explanation": "string — developer-oriented explanation of the vulnerability class",
    "recommended_action": "string — specific remediation step supported by the evidence; null if no fix available",
    "upgrade_target": "string — exact fixed version from fixed_versions, or null if unavailable",
    "verification_steps": ["list of 2-3 concrete steps to verify remediation worked"],
    "confidence": "HIGH if all key fields are present; MEDIUM if some are missing; LOW if very little data"
}


def _build_cache_key(finding: dict) -> str:
    """Stable cache key based on component+vuln identity."""
    key_data = {
        "purl": finding.get("component", {}).get("purl", ""),
        "vuln_id": finding.get("vulnerability", {}).get("id", ""),
    }
    return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()[:16]


def _build_prompt(finding: dict) -> str:
    """Construct the structured prompt from verified finding data. Never adds invented data."""
    comp = finding.get("component", {})
    vuln = finding.get("vulnerability", {})
    dep_ctx = finding.get("dependency_context", {})
    risk_ctx = finding.get("risk_context", {})

    # Build only with what we actually have
    prompt_data = {
        "component": {
            "name": comp.get("name", "UNKNOWN"),
            "version": comp.get("version", "UNKNOWN"),
            "ecosystem": comp.get("ecosystem", "UNKNOWN"),
        },
        "vulnerability": {
            "id": vuln.get("id", "UNKNOWN"),
            "summary": vuln.get("summary") or "No summary available.",
            "severity": vuln.get("severity", "UNKNOWN"),
            "cvss": vuln.get("cvss"),  # null if not available — do not invent
            "affected_versions": vuln.get("affected_versions") or [],
            "fixed_versions": vuln.get("fixed_versions") or [],
            "exploit_status": vuln.get("exploit_status", "UNKNOWN"),
            "source": vuln.get("source", "UNKNOWN"),
        },
        "dependency_context": {
            "is_direct_dependency": dep_ctx.get("direct_dependency", "unknown"),
            "depth": dep_ctx.get("dependency_depth", "unknown"),
        },
        "risk_context": {
            "risk_score": risk_ctx.get("risk_score", "unknown"),
            "risk_factors": risk_ctx.get("risk_factors") or [],
        },
    }

    return (
        f"A SBOMGuard security scan has produced the following verified finding. "
        f"Generate a developer-friendly explanation and remediation guidance.\n\n"
        f"VERIFIED FINDING (authoritative, do not modify):\n"
        f"```json\n{json.dumps(prompt_data, indent=2)}\n```\n\n"
        f"Respond with a JSON object matching this schema exactly:\n"
        f"```json\n{json.dumps(RESPONSE_SCHEMA, indent=2)}\n```"
    )


def _deterministic_fallback(finding: dict) -> dict:
    """
    Returns a deterministic explanation built purely from the structured finding.
    Used when Gemini is unavailable. No LLM involved — this is a template fill.
    """
    comp = finding.get("component", {})
    vuln = finding.get("vulnerability", {})
    risk = finding.get("risk_context", {})

    name = comp.get("name", "UNKNOWN")
    version = comp.get("version", "UNKNOWN")
    vuln_id = vuln.get("id", "UNKNOWN")
    severity = vuln.get("severity", "UNKNOWN")
    cvss = vuln.get("cvss")
    fixed = (vuln.get("fixed_versions") or [])
    upgrade_target = fixed[0] if fixed else None
    risk_score = risk.get("risk_score")

    summary = (
        f"{name} {version} is affected by {vuln_id} ({severity}"
        + (f", CVSS {cvss}" if cvss is not None else "")
        + ")."
    )

    if vuln.get("summary"):
        technical = vuln["summary"]
    else:
        technical = f"A {severity.lower()} severity vulnerability has been identified in {name} {version}."

    if upgrade_target:
        action = f"Upgrade {name} to {upgrade_target} or later and regenerate the lockfile."
        verification = [
            f"Run `npm install` / `pip install -r requirements.txt` to apply the upgrade.",
            f"Regenerate the project SBOM and re-run SBOMGuard.",
            f"Verify {vuln_id} no longer appears in the vulnerability findings.",
        ]
    else:
        action = (
            f"No fixed version is currently known for {vuln_id}. "
            f"Monitor the OSV advisory at https://osv.dev/vulnerability/{vuln_id} for updates. "
            f"Consider removing or replacing {name} if a workaround is unavailable."
        )
        verification = [
            f"Monitor https://osv.dev/vulnerability/{vuln_id} for a fixed version.",
            f"Review the application's use of {name} to identify potential mitigations.",
            f"Re-run SBOMGuard after applying any available vendor patch.",
        ]

    risk_note = ""
    if risk_score and risk_score >= 70:
        risk_note = f" The calculated risk score ({risk_score}/100) is high — prioritize this finding."

    why_matters = (
        f"{name} is installed in the project and the installed version ({version}) "
        f"falls within the affected range reported by {vuln.get('source', 'the security database')}."
        + risk_note
    )

    confidence = "HIGH" if (cvss is not None and upgrade_target) else "MEDIUM" if upgrade_target else "LOW"

    return {
        "summary": summary,
        "why_it_matters": why_matters,
        "technical_explanation": technical,
        "recommended_action": action,
        "upgrade_target": upgrade_target,
        "verification_steps": verification,
        "confidence": confidence,
        "generated_by": "DETERMINISTIC_FALLBACK",
    }


def _call_gemini(prompt: str) -> dict | None:
    """
    Call Gemini flash with the structured prompt.
    Returns parsed JSON dict or None on failure.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel(
            model_name=_GEMINI_MODEL,
            system_instruction=SYSTEM_INSTRUCTION,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,           # Low temperature — we want factual, not creative
                max_output_tokens=1024,
                response_mime_type="application/json",
            )
        )

        response = model.generate_content(prompt, request_options={"timeout": _GEMINI_TIMEOUT})
        raw = response.text.strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        result = json.loads(raw)

        # Safety: strip any fields the LLM might have added that don't belong
        allowed_keys = {
            "summary", "why_it_matters", "technical_explanation",
            "recommended_action", "upgrade_target", "verification_steps", "confidence"
        }
        result = {k: v for k, v in result.items() if k in allowed_keys}
        result["generated_by"] = "GEMINI"
        return result

    except Exception as exc:
        print(f"[LLMExplanation] Gemini call failed: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def explain_finding(finding: dict) -> dict:
    """
    Generate a developer-friendly LLM explanation for a verified security finding.

    Args:
        finding: Structured finding dict containing:
            - component: {name, version, ecosystem, purl, ...}
            - vulnerability: {id, summary, severity, cvss, affected_versions, fixed_versions, ...}
            - dependency_context: {direct_dependency, dependency_depth} (optional)
            - risk_context: {risk_score, risk_factors} (optional)

    Returns:
        Explanation dict with keys: summary, why_it_matters, technical_explanation,
        recommended_action, upgrade_target, verification_steps, confidence, generated_by.
        Always returns a value — falls back to deterministic on LLM failure.
    """
    cache_key = _build_cache_key(finding)
    with _cache_lock:
        if cache_key in _explanation_cache:
            ts, cached = _explanation_cache[cache_key]
            if time.time() - ts < CACHE_TTL_SECONDS:
                return cached

    # Try Gemini first
    gemini_result = None
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if api_key:
        prompt = _build_prompt(finding)
        gemini_result = _call_gemini(prompt)

    result = gemini_result if gemini_result else _deterministic_fallback(finding)

    with _cache_lock:
        _explanation_cache[cache_key] = (time.time(), result)

    return result


def is_llm_available() -> bool:
    """Returns True if a Gemini API key is configured."""
    return bool(os.environ.get("GEMINI_API_KEY", "").strip())
