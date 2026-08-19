import React from 'react';
import { useLocalStorage } from '../../hooks/useLocalStorage';

export default function PoliciesPage({ policies, onTogglePolicy, onCreatePolicy }) {
  const [form, setForm] = useLocalStorage('policy_form', {
    name: '',
    type: 'CVSS_THRESHOLD',
    condition: '>= 9.0',
    action: 'BLOCK'
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.name) {
      alert("Please enter a policy name.");
      return;
    }
    
    await onCreatePolicy(form);
    // Reset form after successful creation
    setForm({ name: '', type: 'CVSS_THRESHOLD', condition: '>= 9.0', action: 'BLOCK' });
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <h3 style={{ fontSize: '1.4rem' }}>Compliance Policy Studio (Policy-as-Code)</h3>
      
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '24px' }}>
        
        {/* Active Rules list */}
        <section className="glass-panel" style={{ padding: '24px' }}>
          <h4 style={{ fontSize: '1.1rem', marginBottom: '16px' }}>Active Compliance Rules</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {policies.map(p => (
              <div key={p.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', borderRadius: '8px', background: 'rgba(0,0,0,0.02)', border: '1px solid var(--border-color)' }}>
                <div>
                  <h5 style={{ fontWeight: 700 }}>{p.name}</h5>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Rule: {p.rule_type} {p.rule_condition} &rarr; Action: <strong>{p.action}</strong></span>
                </div>

                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  <button 
                    className="btn-secondary" 
                    onClick={() => onTogglePolicy(p.id, p.is_active)}
                    style={{ padding: '6px 12px', fontSize: '0.75rem', borderColor: p.is_active ? 'var(--low)' : 'var(--critical)' }}
                  >
                    {p.is_active ? 'ENABLED' : 'DISABLED'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Add rule form */}
        <section className="glass-panel" style={{ padding: '24px', height: 'fit-content' }}>
          <h4 style={{ fontSize: '1.1rem', marginBottom: '16px' }}>Define Custom Rule</h4>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Rule Name</label>
              <input 
                type="text" 
                placeholder="e.g. Block high anomaly packages" 
                value={form.name}
                onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
                style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Rule Trigger Type</label>
              <select 
                value={form.type} 
                onChange={(e) => setForm(f => ({ ...f, type: e.target.value }))}
                style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
              >
                <option value="CVSS_THRESHOLD">CVSS Vulnerability Threshold</option>
                <option value="AI_ANOMALY">AI Anomaly Score</option>
                <option value="FORBIDDEN_LICENSE">Forbidden License Flag</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Condition Pattern</label>
              <input 
                type="text" 
                placeholder="e.g. >= 9.0 or FORBIDDEN" 
                value={form.condition}
                onChange={(e) => setForm(f => ({ ...f, condition: e.target.value }))}
                style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Compliance Action</label>
              <select 
                value={form.action} 
                onChange={(e) => setForm(f => ({ ...f, action: e.target.value }))}
                style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
              >
                <option value="BLOCK">BLOCK (Break CI Build)</option>
                <option value="REVIEW">REVIEW (Log Warn Ticket)</option>
                <option value="PASS">PASS</option>
              </select>
            </div>

            <button type="submit" className="btn-primary" style={{ justifyContent: 'center' }}>
              Publish Rule
            </button>
          </form>
        </section>

      </div>
    </div>
  );
}
