import React, { useState } from 'react';
import { Check } from 'lucide-react';
import { useLocalStorage } from '../../hooks/useLocalStorage';
import { SkeletonTableRows } from '../../components/Loader';
import RemediationWorkspace from './RemediationWorkspace';

export default function TicketsPage({ tickets, isLoading, onUpdateTicketStatus }) {
  const [filter, setFilter] = useLocalStorage('tickets_filter', 'ALL');
  const [activeWorkspace, setActiveWorkspace] = useState(null);

  const filteredTickets = tickets.filter(t => filter === 'ALL' || t.status === filter);

  // Handle action button click
  const handleAction = (ticket) => {
    if (ticket.status === 'OPEN') {
      // Start Work: OPEN → IN_PROGRESS
      onUpdateTicketStatus(ticket.ticket_id, ticket.status);
    } else if (ticket.status === 'IN_PROGRESS') {
      // Resolve: open the Remediation Workspace
      setActiveWorkspace(ticket);
    }
  };

  // Handle resolve from workspace
  const handleResolveFromWorkspace = (ticketId) => {
    onUpdateTicketStatus(ticketId, 'IN_PROGRESS'); // IN_PROGRESS → RESOLVED
    setActiveWorkspace(null);
  };

  // If workspace is active, render it instead of the table
  if (activeWorkspace) {
    return (
      <RemediationWorkspace
        ticket={activeWorkspace}
        onBack={() => setActiveWorkspace(null)}
        onResolve={handleResolveFromWorkspace}
      />
    );
  }

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ fontSize: '1.4rem' }}>Security Remediation Center</h3>
        <select 
          value={filter} 
          onChange={(e) => setFilter(e.target.value)}
          style={{ padding: '8px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
        >
          <option value="ALL">All Tickets</option>
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="RESOLVED">Resolved</option>
        </select>
      </div>
      
      <div className="glass-panel" style={{ padding: '24px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', overflow: 'hidden', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: 'rgba(0,0,0,0.02)', borderBottom: '1px solid var(--border-color)' }}>
              <th style={{ padding: '16px' }}>Ticket ID</th>
              <th style={{ padding: '16px' }}>Package / Component</th>
              <th style={{ padding: '16px' }}>Severity</th>
              <th style={{ padding: '16px' }}>Vulnerability Description</th>
              <th style={{ padding: '16px' }}>Assigned To</th>
              <th style={{ padding: '16px' }}>Status</th>
              <th style={{ padding: '16px' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <SkeletonTableRows cols={7} rows={4} />
            ) : filteredTickets.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No tickets found matching the current filter.
                </td>
              </tr>
            ) : (
              filteredTickets.map(t => (
                <tr key={t.ticket_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '16px', fontWeight: 'bold' }} className="mono-text">{t.ticket_id}</td>
                  <td style={{ padding: '16px' }}>{t.component_name} (v{t.component_version})</td>
                  <td style={{ padding: '16px' }}>
                    <span className={`badge ${t.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}`}>{t.severity}</span>
                  </td>
                  <td style={{ padding: '16px', fontSize: '0.85rem' }}>
                    <strong>{t.recommendation}</strong>
                    <p style={{ color: 'var(--text-secondary)', marginTop: '4px' }}>{t.description}</p>
                  </td>
                  <td style={{ padding: '16px' }}>{t.assignee}</td>
                  <td style={{ padding: '16px' }}>
                    <span style={{ 
                      padding: '4px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600,
                      background: t.status === 'OPEN' ? 'rgba(239, 68, 68, 0.1)' : (t.status === 'IN_PROGRESS' ? 'rgba(234, 179, 8, 0.1)' : 'rgba(16, 185, 129, 0.1)'),
                      color: t.status === 'OPEN' ? 'var(--critical)' : (t.status === 'IN_PROGRESS' ? 'var(--medium)' : 'var(--low)')
                    }}>{t.status}</span>
                  </td>
                  <td style={{ padding: '16px' }}>
                    {t.status !== 'RESOLVED' ? (
                      <button className="btn-secondary" onClick={() => handleAction(t)} style={{ padding: '6px 12px', fontSize: '0.75rem' }}>
                        {t.status === 'OPEN' ? 'Start Work' : 'Resolve Ticket'}
                      </button>
                    ) : (
                      <span style={{ color: 'var(--low)', display: 'flex', alignItems: 'center', gap: '4px' }}><Check size={16} /> Closed</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
