LICENSE_CLASSIFICATIONS = {
    # Permissive
    "MIT": "PERMISSIVE",
    "Apache-2.0": "PERMISSIVE",
    "BSD-3-Clause": "PERMISSIVE",
    "BSD-2-Clause": "PERMISSIVE",
    "ISC": "PERMISSIVE",
    "Unlicense": "PERMISSIVE",
    "WTFPL": "PERMISSIVE",
    
    # Weak Copyleft
    "LGPL-2.1": "RESTRICTED",
    "LGPL-3.0": "RESTRICTED",
    "MPL-2.0": "RESTRICTED",
    "EPL-1.0": "RESTRICTED",
    "EPL-2.0": "RESTRICTED",
    
    # Strong Copyleft / High Risk
    "GPL-2.0": "FORBIDDEN",
    "GPL-3.0": "FORBIDDEN",
    "AGPL-3.0": "FORBIDDEN",
    "SSPL": "FORBIDDEN"
}

def classify_license(license_name):
    """Engine 25: License / Compliance Engine"""
    if not license_name or license_name in ["Unknown", "UNKNOWN", "NOASSERTION"]:
        return "UNKNOWN", "REVIEW", "License is unverified or missing."
        
    # Match standard SPDX IDs
    for spdx_id, category in LICENSE_CLASSIFICATIONS.items():
        if spdx_id.lower() in license_name.lower():
            if category == "PERMISSIVE":
                return spdx_id, "PASS", f"Permissive license ({spdx_id}) approved."
            elif category == "RESTRICTED":
                return spdx_id, "REVIEW", f"Restricted license ({spdx_id}) requires legal review."
            elif category == "FORBIDDEN":
                return spdx_id, "BLOCK", f"Forbidden copyleft license ({spdx_id}) is blocked by corporate policy."
                
    # Default to review if unrecognized but present
    return license_name, "REVIEW", f"Unrecognized license '{license_name}' requires security review."
