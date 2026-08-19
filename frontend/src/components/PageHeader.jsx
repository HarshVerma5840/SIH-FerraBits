import React from 'react';

export default function PageHeader() {
  return (
    <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div>
        <span style={{ color: 'var(--primary)', fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Secure Software Supply Chain</span>
        <h1 style={{ fontSize: '2.2rem', marginTop: '4px' }}>AI Compliance & Assessment Platform</h1>
      </div>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', background: 'rgba(0,0,0,0.03)', padding: '8px 16px', borderRadius: '30px', border: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
          <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Security Operations Center</span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Role: Administrator</span>
        </div>
        <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'linear-gradient(135deg, #6366f1 0%, #3b82f6 100%)', display: 'flex', justifyContent: 'center', alignItems: 'center', fontWeight: 800 }}>
          AD
        </div>
      </div>
    </header>
  );
}
