import React from 'react';
import { SkeletonTableRows } from '../../components/Loader';

export default function AuditPage({ auditLogs, isLoading }) {
  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <h3 style={{ fontSize: '1.4rem' }}>Security Operations Audit Trail</h3>
      
      <div className="glass-panel" style={{ padding: '24px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', overflow: 'hidden', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: 'rgba(0,0,0,0.02)', borderBottom: '1px solid var(--border-color)' }}>
              <th style={{ padding: '16px' }}>Timestamp</th>
              <th style={{ padding: '16px' }}>Operator</th>
              <th style={{ padding: '16px' }}>Compliance Action</th>
              <th style={{ padding: '16px' }}>Action details</th>
              <th style={{ padding: '16px' }}>Client IP</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <SkeletonTableRows cols={5} rows={4} />
            ) : auditLogs.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No audit logs recorded yet.
                </td>
              </tr>
            ) : (
              auditLogs.map((l, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '16px' }} className="mono-text">{new Date(l.timestamp).toLocaleString()}</td>
                  <td style={{ padding: '16px', fontWeight: 'bold' }}>{l.username}</td>
                  <td style={{ padding: '16px' }}>
                    <span style={{ 
                      padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 700,
                      background: l.action.includes('fail') || l.action.includes('block') ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                      color: l.action.includes('fail') || l.action.includes('block') ? 'var(--critical)' : 'var(--low)'
                    }}>{l.action.toUpperCase()}</span>
                  </td>
                  <td style={{ padding: '16px', fontSize: '0.85rem' }}>{l.details}</td>
                  <td style={{ padding: '16px' }} className="mono-text">{l.ip_address}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
