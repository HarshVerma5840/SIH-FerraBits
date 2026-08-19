import React from 'react';
import { XCircle } from 'lucide-react';

export default function ComplianceGate() {
  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div className="glass-panel" style={{ padding: '24px', borderLeft: '4px solid var(--critical)' }}>
        <h4 style={{ fontSize: '1.1rem', color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
          <XCircle /> CI/CD Build Gate Decision: BLOCKED
        </h4>
        <p style={{ fontSize: '0.85rem' }}>The security compliance gate failed because components violated active policy rules. Critical CVEs and malicious code features were detected.</p>
      </div>

      <section className="glass-panel" style={{ padding: '24px' }}>
        <h4 style={{ fontSize: '1rem', marginBottom: '16px' }}>Developer Compliance Diagnostic Output</h4>
        <pre style={{ background: '#05070c', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)', color: '#ef4444', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
{`====================================================
 SBOMGUARD CI/CD GATE SECURITY ANALYSIS REPORT
 STATUS: BLOCK (Exit Code: 2)
====================================================

[!] Flagged 3 package violations:
  1. [BLOCK] org.apache.logging.log4j:log4j-core@2.14.0 (maven)
     - Vulnerability CVSS score 10.0 triggers BLOCK rule (>= 9.0)
  2. [BLOCK] sih-malicious-package@1.0.0 (npm)
     - AI Anomaly score 85 triggers REVIEW/BLOCK rule (>= 80)
  3. [REVIEW] lodash@4.17.11 (npm)
     - Vulnerability CVSS score 7.4 triggers REVIEW threshold (>= 7.0)

Remediation Recommendations:
  - org.apache.logging.log4j:log4j-core: Upgrade log4j-core to version 2.15.0 or higher.
  - lodash: Upgrade lodash to version 4.17.21.

====================================================`}
        </pre>
      </section>
    </div>
  );
}
