import React, { useState } from 'react';
import { useLocalStorage } from '../../../hooks/useLocalStorage';
import { API_BASE, MOCK_PROJECTS } from '../../../constants/mock';
import { Spinner } from '../../../components/Loader';

export default function WhatIfSimulator({ project, isOfflineMode }) {
  const [whatIfPurl, setWhatIfPurl] = useLocalStorage('whatif_purl', '');
  const [whatIfVersion, setWhatIfVersion] = useLocalStorage('whatif_version', '');
  const [whatIfResult, setWhatIfResult] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);

  const handleWhatIfSimulation = async (e) => {
    e.preventDefault();
    if (!whatIfPurl || !whatIfVersion) {
      alert("Please specify both target package and version.");
      return;
    }
    
    setIsSimulating(true);
    if (isOfflineMode) {
      setTimeout(() => {
        const proj = MOCK_PROJECTS.find(p => p.id === project.id);
        const originalRisk = proj ? proj.risk_score : 95;
        
        setWhatIfResult({
          status: "SIMULATION",
          upgraded_package: whatIfPurl.split("/").pop().split("@")[0],
          target_version: whatIfVersion,
          projected_total_risk: whatIfPurl.includes("log4j") ? 65 : 85,
          projected_vulnerability_count: whatIfPurl.includes("log4j") ? 4 : 5,
          projected_critical_count: whatIfPurl.includes("log4j") ? 0 : 1,
          projected_high_count: 3
        });
        setIsSimulating(false);
      }, 700);
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/projects/${project.id}/whatif`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            upgrade_purl: whatIfPurl,
            target_version: whatIfVersion
          })
        });
        if (r.ok) {
          setWhatIfResult(await r.json());
        }
      } catch (err) {
        alert("Error running simulation on backend: " + err.message);
      } finally {
        setIsSimulating(false);
      }
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h4 style={{ fontSize: '1rem', marginBottom: '16px' }}>Run Simulation (Assess hypothetical patch risk changes)</h4>
        <form onSubmit={handleWhatIfSimulation} style={{ display: 'flex', gap: '16px', alignItems: 'flex-end' }}>
          <div style={{ flex: 1.5 }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Target Component (PURL)</label>
            <select 
              value={whatIfPurl} 
              onChange={(e) => setWhatIfPurl(e.target.value)}
              style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
            >
              <option value="">-- Choose package to upgrade --</option>
              {project?.components
                ?.filter(c => c.vulnerabilities.length > 0)
                .map(c => (
                  <option key={c.purl} value={c.purl}>{c.name} (Current: {c.version})</option>
                ))}
            </select>
          </div>

          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Simulation Upgrade Version</label>
            <input 
              type="text" 
              placeholder="e.g. 2.15.0" 
              value={whatIfVersion}
              onChange={(e) => setWhatIfVersion(e.target.value)}
              style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
            />
          </div>

          <button type="submit" className="btn-primary" style={{ padding: '10px 24px' }} disabled={isSimulating}>
            {isSimulating ? <><Spinner size={16} color="white" /> Running Sandbox...</> : 'Run Sandbox Simulation'}
          </button>
        </form>
      </div>

      {whatIfResult && (
        <div className="glass-panel" style={{ padding: '24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
          <div>
            <h4 style={{ fontSize: '1.1rem', color: 'var(--primary)', marginBottom: '16px' }}>Projected Risk Shift</h4>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <span>Current Max Risk:</span>
                <span style={{ fontWeight: 700, color: 'var(--critical)' }}>95/100</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <span>Projected Max Risk:</span>
                <span style={{ fontWeight: 700, color: whatIfResult.projected_total_risk > 70 ? 'var(--high)' : 'var(--low)' }}>{whatIfResult.projected_total_risk}/100</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <span>Risk Delta:</span>
                <span style={{ fontWeight: 700, color: 'var(--low)' }}>-{95 - whatIfResult.projected_total_risk} Risk points</span>
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ fontSize: '1.1rem', color: 'var(--info)', marginBottom: '16px' }}>Projected Vulnerability Reductions</h4>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <span>Critical Disclosures:</span>
                <span>1 &rarr; <span style={{ fontWeight: 700, color: 'var(--low)' }}>{whatIfResult.projected_critical_count}</span></span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <span>Remaining Vuln count:</span>
                <span>5 &rarr; <span style={{ fontWeight: 700 }}>{whatIfResult.projected_vulnerability_count}</span></span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
