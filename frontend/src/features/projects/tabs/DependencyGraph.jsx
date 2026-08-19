import React, { useState } from 'react';
import { GitBranch, HelpCircle } from 'lucide-react';

export default function DependencyGraph() {
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);
  const [graphBlastRadius, setGraphBlastRadius] = useState(null);

  return (
    <div className="animate-fade-in glass-panel" style={{ padding: '24px', display: 'grid', gridTemplateColumns: '2fr 1.2fr', gap: '24px' }}>
      
      {/* SVG Graphic Canvas */}
      <div style={{ border: '1px solid var(--border-color)', borderRadius: '12px', background: '#ffffff', height: '400px', position: 'relative', overflow: 'hidden' }}>
        <span style={{ position: 'absolute', top: '12px', left: '12px', fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>Interactive Dependency Node Graph</span>
        
        <svg style={{ width: '100%', height: '100%' }}>
          {/* Define arrows */}
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(0,0,0,0.15)" />
            </marker>
          </defs>

          {/* Hardcoded SVG nodes representing relations */}
          {/* Edges */}
          <line x1="60" y1="200" x2="200" y2="100" stroke="rgba(0,0,0,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
          <line x1="60" y1="200" x2="200" y2="200" stroke="rgba(0,0,0,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
          <line x1="60" y1="200" x2="200" y2="300" stroke="rgba(0,0,0,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
          <line x1="200" y1="100" x2="340" y2="100" stroke="rgba(0,0,0,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
          
          {/* Node: Application Root */}
          <circle cx="60" cy="200" r="22" fill="#6366f1" style={{ cursor: 'pointer' }} onClick={() => {
            setSelectedGraphNode({ name: "Application Root", version: "1.0.0", risk_score: 0, purl: "root", description: "Your target scanned project repository workspace." });
            setGraphBlastRadius(null);
          }} />
          <text x="60" y="235" fill="var(--text-primary)" fontSize="10" textAnchor="middle" fontWeight="bold">Application</text>
          
          {/* Node: lodash */}
          <circle cx="200" cy="100" r="18" fill="var(--high)" style={{ cursor: 'pointer' }} onClick={() => {
            setSelectedGraphNode({ name: "lodash", version: "4.17.11", risk_score: 75, purl: "pkg:npm/lodash@4.17.11", description: "Prototype pollution vulnerability present (CVE-2019-10744)." });
            setGraphBlastRadius({ path: "Application -> lodash -> follow-redirects", count: 1 });
          }} />
          <text x="200" y="132" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">lodash</text>

          {/* Node: log4j */}
          <circle cx="200" cy="200" r="18" fill="var(--critical)" style={{ cursor: 'pointer' }} onClick={() => {
            setSelectedGraphNode({ name: "log4j-core", version: "2.14.0", risk_score: 95, purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", description: "Critical JNDI RCE vulnerability present (CVE-2021-44228)." });
            setGraphBlastRadius({ path: "Application -> log4j-core", count: 0 });
          }} />
          <text x="200" y="232" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">log4j-core</text>

          {/* Node: express */}
          <circle cx="200" cy="300" r="18" fill="var(--low)" style={{ cursor: 'pointer' }} onClick={() => {
            setSelectedGraphNode({ name: "express", version: "4.17.1", risk_score: 10, purl: "pkg:npm/express@4.17.1", description: "Secure, no vulnerabilities detected." });
            setGraphBlastRadius(null);
          }} />
          <text x="200" y="332" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">express</text>

          {/* Node: follow-redirects */}
          <circle cx="340" cy="100" r="18" fill="var(--high)" style={{ cursor: 'pointer' }} onClick={() => {
            setSelectedGraphNode({ name: "follow-redirects", version: "1.15.2", risk_score: 65, purl: "pkg:npm/follow-redirects@1.15.2", description: "Transitive dependency of lodash containing redirect leak." });
            setGraphBlastRadius({ path: "Application -> lodash -> follow-redirects", count: 1 });
          }} />
          <text x="340" y="132" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">follow-redirects</text>
        </svg>
      </div>

      {/* Blast Radius details */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <h4 style={{ fontSize: '1.1rem', color: 'var(--primary)' }}>Threat Path Intelligence</h4>
        
        {selectedGraphNode ? (
          <div style={{ background: 'rgba(0,0,0,0.02)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Node Name:</span>
              <h5 style={{ fontSize: '1rem', fontWeight: 700 }}>{selectedGraphNode.name}</h5>
            </div>
            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Package PURL:</span>
              <span className="mono-text" style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>{selectedGraphNode.purl}</span>
            </div>
            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Severity / Risk:</span>
              <span style={{ fontWeight: 700, display: 'block', color: selectedGraphNode.risk_score > 60 ? 'var(--critical)' : 'var(--low)' }}>{selectedGraphNode.risk_score}/100</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{selectedGraphNode.description}</p>
            
            {graphBlastRadius && (
              <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '12px', marginTop: '8px' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--high)', fontWeight: 700, display: 'block', marginBottom: '4px' }}>Blast Radius: {graphBlastRadius.count} Downstream dependents affected</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)', background: 'rgba(0,0,0,0.05)', padding: '6px', borderRadius: '4px' }}>
                  <GitBranch size={12} /> <span className="mono-text">{graphBlastRadius.path}</span>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <HelpCircle size={32} style={{ margin: '0 auto 12px auto', opacity: 0.5 }} />
            <p>Click any node inside the canvas to trace its threat propagation path and calculate blast radius metrics.</p>
          </div>
        )}
      </div>
    </div>
  );
}
