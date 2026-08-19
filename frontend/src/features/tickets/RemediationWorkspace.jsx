import React from 'react';
import { ArrowLeft, Clock } from 'lucide-react';
import './RemediationWorkspace.css';

export default function RemediationWorkspace({ ticket, onBack, onResolve }) {
  return (
    <div className="remediation-workspace">
      <div className="workspace-header">
        <button className="btn-secondary" onClick={onBack}>
          <ArrowLeft size={16} /> Back to Tickets
        </button>
        <div className="header-info">
          <h2>{ticket?.ticket_id || 'Ticket Details'}</h2>
          <span className={`badge badge-${ticket?.severity?.toLowerCase() || 'default'}`}>
            {ticket?.severity || 'UNKNOWN'}
          </span>
        </div>
      </div>
      
      <div className="workspace-body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', color: 'var(--text-secondary)' }}>
        <Clock size={48} style={{ opacity: 0.2, marginBottom: '20px' }} />
        <h3>Remediation Workspace</h3>
        <p style={{ maxWidth: '400px', textAlign: 'center', margin: '10px 0 20px 0' }}>
          This module is under construction and will be added later.
        </p>
        <button className="btn-primary" onClick={() => onResolve && onResolve(ticket?.ticket_id)}>
          Mark as Resolved
        </button>
      </div>
    </div>
  );
}
