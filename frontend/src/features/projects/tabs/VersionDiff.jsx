import React, { useState } from 'react';
import { useLocalStorage } from '../../../hooks/useLocalStorage';
import { API_BASE } from '../../../constants/mock';
import { Spinner } from '../../../components/Loader';

export default function VersionDiff({ project, versionHistory, isOfflineMode }) {
  const [selectedVersionBase, setSelectedVersionBase] = useLocalStorage('diff_base', '');
  const [selectedVersionHead, setSelectedVersionHead] = useLocalStorage('diff_head', '');
  const [diffResult, setDiffResult] = useState(null);
  const [isDiffLoading, setIsDiffLoading] = useState(false);

  const handleCompareVersions = async () => {
    if (!selectedVersionBase || !selectedVersionHead) {
      alert("Please select both base and head versions to compare.");
      return;
    }
    
    setIsDiffLoading(true);
    if (isOfflineMode) {
      setTimeout(() => {
        setDiffResult({
          added: [
            { name: "requests", version: "2.31.0", ecosystem: "pypi", license: "Apache-2.0", type: "library" }
          ],
          removed: [],
          updated: [
            { name: "lodash", old_version: "4.17.9", new_version: "4.17.11", old_license: "MIT", new_license: "MIT" }
          ]
        });
        setIsDiffLoading(false);
      }, 500);
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/projects/${project.id}/diff/${selectedVersionBase}/${selectedVersionHead}`);
        if (r.ok) {
          setDiffResult(await r.json());
        }
      } catch (e) {
        alert("Failed to compute diff on backend: " + e.message);
      } finally {
        setIsDiffLoading(false);
      }
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Selectors */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', gap: '16px', alignItems: 'flex-end' }}>
        <div style={{ flex: 1 }}>
          <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: 600 }}>Select Base Scan Version</label>
          <select 
            value={selectedVersionBase}
            onChange={(e) => setSelectedVersionBase(e.target.value)}
            style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
          >
            <option value="">-- Choose Base --</option>
            {versionHistory.map(v => (
              <option key={v.sbom_id} value={v.sbom_id}>Version {v.version_number} ({v.components_count} packages) - {new Date(v.created_at).toLocaleDateString()}</option>
            ))}
          </select>
        </div>

        <div style={{ flex: 1 }}>
          <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: 600 }}>Select Head Scan Version</label>
          <select 
            value={selectedVersionHead}
            onChange={(e) => setSelectedVersionHead(e.target.value)}
            style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
          >
            <option value="">-- Choose Head --</option>
            {versionHistory.map(v => (
              <option key={v.sbom_id} value={v.sbom_id}>Version {v.version_number} ({v.components_count} packages) - {new Date(v.created_at).toLocaleDateString()}</option>
            ))}
          </select>
        </div>

        <button className="btn-primary" onClick={handleCompareVersions} style={{ padding: '10px 24px' }} disabled={isDiffLoading}>
          {isDiffLoading ? <><Spinner size={16} color="white" /> Computing...</> : 'Compute Diff Tree'}
        </button>
      </div>

      {/* Diff Output */}
      {diffResult && (
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <h4 style={{ fontSize: '1rem', color: 'var(--primary)' }}>SBOM Diff Logs</h4>
          
          {diffResult.added.length === 0 && diffResult.removed.length === 0 && diffResult.updated.length === 0 ? (
            <span style={{ fontSize: '0.85rem' }}>No package shifts detected between these scan sessions.</span>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.85rem' }}>
              {diffResult.added.map((a, i) => (
                <div key={i} style={{ padding: '8px', borderRadius: '6px', background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)', color: 'var(--low)' }}>
                  <strong>+ ADDED Component:</strong> {a.name}@{a.version} ({a.ecosystem})
                </div>
              ))}
              
              {diffResult.updated.map((u, i) => (
                <div key={i} style={{ padding: '8px', borderRadius: '6px', background: 'rgba(59, 130, 246, 0.05)', border: '1px solid rgba(59, 130, 246, 0.2)', color: 'var(--info)' }}>
                  <strong>&Delta; MODIFIED Version:</strong> {u.name} upgraded from {u.old_version} to {u.new_version}
                </div>
              ))}
              
              {diffResult.removed.map((r, i) => (
                <div key={i} style={{ padding: '8px', borderRadius: '6px', background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.2)', color: 'var(--critical)' }}>
                  <strong>- REMOVED Component:</strong> {r.name}@{r.version}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
