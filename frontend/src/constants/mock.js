// All mock/fallback data — previously embedded in App.jsx
// Used when backend is unreachable (offline demo mode)

export const API_BASE = "http://localhost:8000";

export const MOCK_PROJECTS = [
  { id: 1, name: "E-Commerce Microservice Hub", description: "Production retail server containing web manifests, dockerfiles, and python worker scripts.", created_at: "2026-08-17T09:00:00Z", latest_scan_status: "COMPLETED", latest_scan_id: 1, vulnerability_count: 5, risk_score: 95, risk_level: "CRITICAL", quality_score: 82 },
  { id: 2, name: "AI Analytics Pipeline", description: "Machine learning orchestrator utilizing pandas, numpy, and flask worker nodes.", created_at: "2026-08-17T08:30:00Z", latest_scan_status: "COMPLETED", latest_scan_id: 2, vulnerability_count: 2, risk_score: 65, risk_level: "HIGH", quality_score: 94 },
  { id: 3, name: "Secure Authentication Gateway", description: "Identity provider service with strict CORS, JWT, and cryptographically verified packages.", created_at: "2026-08-17T08:15:00Z", latest_scan_status: "COMPLETED", latest_scan_id: 3, vulnerability_count: 0, risk_score: 12, risk_level: "LOW", quality_score: 98 }
];

export const MOCK_COMPONENTS = [
  { id: 1, name: "lodash", version: "4.17.11", ecosystem: "npm", purl: "pkg:npm/lodash@4.17.11", license: "MIT", depth: 0, direct: true, source_file: "package.json", confidence: 0.90, risk_score: 75, risk_level: "HIGH", explanation: "Contains prototype pollution vulnerability (CVE-2019-10744, CVE-2020-8203) with high execution priority.", anomaly_score: 15, vulnerabilities: [{ cve_id: "CVE-2019-10744", cvss_score: 9.8, severity: "CRITICAL", description: "Prototype pollution in defaultsDeep, merge, and mergeWith." }, { cve_id: "CVE-2020-8203", cvss_score: 7.4, severity: "HIGH", description: "Prototype pollution in lodash when parsing object keys." }] },
  { id: 2, name: "follow-redirects", version: "1.15.2", ecosystem: "npm", purl: "pkg:npm/follow-redirects@1.15.2", license: "MIT", depth: 1, direct: false, source_file: "package-lock.json", confidence: 0.99, risk_score: 65, risk_level: "HIGH", explanation: "Transitive vulnerability (CVE-2023-26159) with redirect credentials leakage.", anomaly_score: 12, vulnerabilities: [{ cve_id: "CVE-2023-26159", cvss_score: 7.5, severity: "HIGH", description: "Redirection leak vulnerability when sending credentials." }] },
  { id: 3, name: "org.apache.logging.log4j:log4j-core", version: "2.14.0", ecosystem: "maven", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", license: "Apache-2.0", depth: 0, direct: true, source_file: "pom.xml", confidence: 0.90, risk_score: 95, risk_level: "CRITICAL", explanation: "Critical JNDI RCE disclosure (CVE-2021-44228) with maximum blast radius impact.", anomaly_score: 8, vulnerabilities: [{ cve_id: "CVE-2021-44228", cvss_score: 10.0, severity: "CRITICAL", description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints." }] },
  { id: 4, name: "sih-malicious-package", version: "1.0.0", ecosystem: "npm", purl: "pkg:npm/sih-malicious-package@1.0.0", license: "Unknown", depth: 0, direct: true, source_file: "package.json", confidence: 0.90, risk_score: 88, risk_level: "CRITICAL", explanation: "AI Anomaly engine flagged package due to installation script combined with 85% obfuscated lines and 7 external socket connections.", anomaly_score: 85, vulnerabilities: [] },
  { id: 5, name: "express", version: "4.17.1", ecosystem: "npm", purl: "pkg:npm/express@4.17.1", license: "MIT", depth: 0, direct: true, source_file: "package.json", confidence: 0.90, risk_score: 10, risk_level: "LOW", explanation: "Passed automated security compliance checks.", anomaly_score: 4, vulnerabilities: [] }
];

export const MOCK_TICKETS = [
  { ticket_id: "SEC-B29E3C", component_name: "org.apache.logging.log4j:log4j-core", component_version: "2.14.0", severity: "CRITICAL", risk_score: 95, description: "Automated policy violation ticket: Critical JNDI RCE disclosure (CVE-2021-44228).", recommendation: "Upgrade log4j-core to version 2.15.0 or higher.", status: "OPEN", assignee: "Unassigned" },
  { ticket_id: "SEC-634A1B", component_name: "lodash", component_version: "4.17.11", severity: "HIGH", risk_score: 75, description: "Automated policy violation ticket: Prototype pollution vulnerability (CVE-2019-10744).", recommendation: "Upgrade lodash to version 4.17.21.", status: "IN_PROGRESS", assignee: "Alex Rivera" }
];

export const MOCK_AUDIT = [
  { timestamp: "2026-08-17T09:12:00Z", username: "admin", action: "scan_completed", details: "Completed security scan for project 'E-Commerce Microservice Hub' (Quality: 82, Gate: BLOCK)", ip_address: "127.0.0.1" },
  { timestamp: "2026-08-17T09:05:00Z", username: "admin", action: "update_policy", details: "Updated policy 1 ('Block Critical CVSS')", ip_address: "127.0.0.1" },
  { timestamp: "2026-08-17T09:01:00Z", username: "admin", action: "scan_triggered", details: "Triggered scan 1 via file upload for project 'E-Commerce Microservice Hub'", ip_address: "127.0.0.1" }
];

export const MOCK_POLICIES = [
  { id: 1, name: "Block Critical CVSS", rule_type: "CVSS_THRESHOLD", rule_condition: ">= 9.0", action: "BLOCK", is_active: true },
  { id: 2, name: "Review High CVSS", rule_type: "CVSS_THRESHOLD", rule_condition: ">= 7.0", action: "REVIEW", is_active: true },
  { id: 3, name: "Review AI Anomalies", rule_type: "AI_ANOMALY", rule_condition: ">= 80", action: "REVIEW", is_active: true },
  { id: 4, name: "Block Copyleft Licenses", rule_type: "FORBIDDEN_LICENSE", rule_condition: "FORBIDDEN", action: "BLOCK", is_active: true }
];

export const MOCK_VERSION_HISTORY = [
  { version_number: 2, sbom_id: 200, created_at: "2026-08-17T09:00:00Z", components_count: 5, scan_id: 1, scan_triggered_by: "admin" },
  { version_number: 1, sbom_id: 100, created_at: "2026-08-16T12:00:00Z", components_count: 4, scan_id: 2, scan_triggered_by: "system" }
];
