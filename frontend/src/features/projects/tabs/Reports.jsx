import React from 'react';
import { Download } from 'lucide-react';
import { API_BASE } from '../../../constants/mock';

export default function Reports({ project }) {
  return (
    <div className="animate-fade-in glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <h4 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>Compliance Document Generator</h4>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>Download standardized CycloneDX & SPDX software bill of material files or export CSV security reports.</p>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
        <a href={`${API_BASE}/api/reports/project/${project.id}/cyclonedx`} download style={{ textDecoration: 'none' }}>
          <button className="btn-secondary" style={{ width: '100%', justifyContent: 'center', padding: '16px' }}>
            <Download size={20} color="var(--primary)" /> Download CycloneDX (JSON)
          </button>
        </a>
        
        <a href={`${API_BASE}/api/reports/project/${project.id}/spdx`} download style={{ textDecoration: 'none' }}>
          <button className="btn-secondary" style={{ width: '100%', justifyContent: 'center', padding: '16px' }}>
            <Download size={20} color="var(--info)" /> Download SPDX (JSON)
          </button>
        </a>

        <a href={`${API_BASE}/api/reports/project/${project.id}/csv`} download style={{ textDecoration: 'none' }}>
          <button className="btn-secondary" style={{ width: '100%', justifyContent: 'center', padding: '16px' }}>
            <Download size={20} color="var(--low)" /> Download CSV Audit Report
          </button>
        </a>
      </div>
    </div>
  );
}
