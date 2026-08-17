import unittest
import os
import shutil

from backend.app.engines.discovery_engine import discover_manifests, discover_dependencies
from backend.app.engines.sbom_engine import generate_cyclonedx, generate_spdx, sign_sbom
from backend.app.engines.security_engine import run_vulnerability_detection
from backend.app.engines.ai_engine import classify_malicious_dependency
from backend.app.engines.automation_engine import evaluate_policy

class TestSBOMGuardEngines(unittest.TestCase):

    def setUp(self):
        # Create temp folder for testing manifests
        self.test_dir = "./temp_test_manifests"
        os.makedirs(self.test_dir, exist_ok=True)
        
        # Write dummy package.json
        with open(os.path.join(self.test_dir, "package.json"), "w") as f:
            f.write('{"name":"test-project", "dependencies": {"lodash": "4.17.11"}}')
            
    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_discovery_engine(self):
        manifests = discover_manifests(self.test_dir)
        self.assertTrue(len(manifests) > 0)
        components = discover_dependencies(manifests)
        self.assertTrue(len(components) > 0)
        lodash_found = any(c["name"] == "lodash" and c.get("version_spec") == "4.17.11" for c in components)
        self.assertTrue(lodash_found)

    def test_vulnerability_matching(self):
        mock_component = {"name": "lodash", "version": "4.17.11", "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.11"}
        vulns = run_vulnerability_detection([mock_component])
        self.assertTrue(len(vulns) > 0)
        cves = [v["cve_id"] for v in vulns]
        self.assertIn("CVE-2019-10744", cves)

    def test_ai_risk_score(self):
        mock_component = {"name": "lodash", "version": "4.17.11", "ecosystem": "npm", "has_install_script": False}
        pred = classify_malicious_dependency(mock_component)
        self.assertIn("classification", pred)
        self.assertIn("probability", pred)

    def test_sbom_generation(self):
        manifests = discover_manifests(self.test_dir)
        components = discover_dependencies(manifests)
        
        cdx_json = generate_cyclonedx("test-project", components)
        self.assertIn("bomFormat", cdx_json)
        self.assertIn("components", cdx_json)
        
        spdx_json = generate_spdx("test-project", components)
        self.assertIn("spdxVersion", spdx_json)
        
    def test_policy_enforcement(self):
        rules = [
            {"rule_type": "CVSS_THRESHOLD", "condition": ">= 9.0", "action": "BLOCK"}
        ]
        
        bad_component = {
            "name": "log4j-core",
            "version": "2.14.0"
        }
        vulnerabilities = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0}]
        
        result = evaluate_policy(bad_component, vulnerabilities, 95.0, rules)
        self.assertEqual(result["action"], "BLOCK")
        self.assertTrue(len(result["reasons"]) > 0)

    def test_whatif_simulation(self):
        from backend.app.engines.ai_engine import run_whatif_simulation
        from backend.app.engines.security_engine import OFFLINE_VULN_DB
        components = [
            {
                "name": "lodash",
                "version": "4.17.11",
                "ecosystem": "npm",
                "purl": "pkg:npm/lodash@4.17.11",
                "type": "library",
                "direct": True
            }
        ]
        result = run_whatif_simulation(components, "pkg:npm/lodash@4.17.11", "4.17.21", OFFLINE_VULN_DB)
        self.assertEqual(result["status"], "SIMULATION")
        self.assertEqual(result["upgraded_package"], "lodash")
        self.assertEqual(result["target_version"], "4.17.21")
        self.assertTrue("projected_total_risk" in result)

if __name__ == "__main__":
    unittest.main()
