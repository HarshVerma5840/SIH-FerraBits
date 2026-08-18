import sys
import os
import time
import argparse
import requests

def parse_arguments():
    parser = argparse.ArgumentParser(description="SBOMGuard AI Security Gate CLI")
    parser.add_argument("--api-url", default="http://localhost:8000", help="URL of the SBOMGuard backend API")
    parser.add_argument("--project-id", type=int, default=1, help="Target project ID inside the platform")
    parser.add_argument("--path", default=".", help="Path to local folder/repository manifest root")
    parser.add_argument("--token", help="JWT Authentication token (optional)")
    return parser.parse_args()

def trigger_scan(api_url, project_id, target_path, headers):
    url = f"{api_url}/api/scans/local"
    payload = {
        "project_id": project_id,
        "directory_path": target_path
    }
    try:
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code != 200:
            print(f"[ERROR] Failed to schedule scan (status code {r.status_code}): {r.text}")
            sys.exit(3)
        data = r.json()
        scan_id = data["scan_id"]
        print(f"[*] Scan scheduled successfully. Scan ID: {scan_id}")
        return scan_id
    except Exception as e:
        print(f"[ERROR] Backend API unreachable at {api_url}: {str(e)}")
        sys.exit(3)

def poll_scan_status(api_url, scan_id, headers):
    status = "PENDING"
    print("[*] Polling scan status in background...")
    while status in ["PENDING", "RUNNING"]:
        time.sleep(2)
        try:
            r = requests.get(f"{api_url}/api/scans/{scan_id}/status", headers=headers)
            if r.status_code == 200:
                status = r.json()["status"]
                print(f"    - Current scan status: {status}")
            else:
                print(f"[WARNING] Failed to fetch scan status: {r.text}")
        except Exception as e:
            print(f"[WARNING] Connection issue during status polling: {e}")
            
    if status == "FAILED":
        print("[ERROR] Scan pipeline execution failed on backend.")
        try:
            r = requests.get(f"{api_url}/api/scans/{scan_id}/logs", headers=headers)
            if r.status_code == 200:
                print("\nBackend Logs:")
                print(r.json()["logs"])
        except Exception:
            pass
        sys.exit(3)
    return status

def fetch_project_details(api_url, project_id, headers):
    print("[*] Scan completed. Retrieving policy evaluation and security gate decision...")
    try:
        r = requests.get(f"{api_url}/api/projects/{project_id}", headers=headers)
        if r.status_code != 200:
            print(f"[ERROR] Failed to fetch project details: {r.text}")
            sys.exit(3)
        return r.json()
    except Exception as e:
        print(f"[ERROR] Failed to connect to API: {str(e)}")
        sys.exit(3)

def evaluate_compliance_gate(components):
    exit_code = 0
    blocked_packages = []
    reviewed_packages = []
    
    for c in components:
        reasons = []
        action = "PASS"
        
        # Simulating client-side mirror policy evaluation matching backend
        max_cvss = max([v["cvss_score"] for v in c.get("vulnerabilities", []) if v.get("cvss_score")] or [0])
        
        if max_cvss >= 9.0:
            action = "BLOCK"
            reasons.append(f"CVSS score {max_cvss} exceeds BLOCK threshold (9.0)")
        elif max_cvss >= 7.0:
            action = "REVIEW"
            reasons.append(f"CVSS score {max_cvss} triggers REVIEW threshold (7.0)")
            
        if c.get("anomaly_score", 0) >= 80:
            action = "REVIEW"
            reasons.append(f"AI Anomaly score {c.get('anomaly_score')} exceeds REVIEW threshold (80)")
            
        if action == "BLOCK":
            blocked_packages.append((c["name"], c.get("version"), reasons))
            exit_code = 2
        elif action == "REVIEW":
            reviewed_packages.append((c["name"], c.get("version"), reasons))
            if exit_code != 2:
                exit_code = 1
                
    return exit_code, blocked_packages, reviewed_packages

def print_gate_report(exit_code, blocked_packages, reviewed_packages):
    print("\n" + "="*60)
    print(" SBOMGUARD SECURITY GATE REPORT")
    print("="*60)
    
    if exit_code == 0:
        print("\n[SUCCESS] All packages conformed to compliance policies. Build passed.")
    else:
        if blocked_packages:
            print(f"\n[FAIL] Blocked {len(blocked_packages)} packages:")
            for name, ver, reasons in blocked_packages:
                print(f"  - {name}@{ver}")
                for r in reasons:
                    print(f"    Reason: {r}")
        if reviewed_packages:
            print(f"\n[WARNING] Flagged {len(reviewed_packages)} packages for security review:")
            for name, ver, reasons in reviewed_packages:
                print(f"  - {name}@{ver}")
                for r in reasons:
                    print(f"    Reason: {r}")
                    
    print("\n" + "="*60)
    if exit_code == 0:
        result_str = 'PASSED'
    elif exit_code == 1:
        result_str = 'WARNING (REVIEW)'
    else:
        result_str = 'FAILED (BLOCKED)'
    print(f" FINAL RESULT: {result_str}")
    print(f" Exit Code: {exit_code}")
    print("="*60)

def main():
    args = parse_arguments()
    
    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        print(f"[ERROR] Specified scan path does not exist: {target_path}")
        sys.exit(3)
        
    print(f"[*] Initializing SBOMGuard compliance check for path: {target_path}")
    
    headers = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
        
    scan_id = trigger_scan(args.api_url, args.project_id, target_path, headers)
    poll_scan_status(args.api_url, scan_id, headers)
    details = fetch_project_details(args.api_url, args.project_id, headers)
    
    components = details.get("components", [])
    exit_code, blocked_packages, reviewed_packages = evaluate_compliance_gate(components)
    print_gate_report(exit_code, blocked_packages, reviewed_packages)
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
