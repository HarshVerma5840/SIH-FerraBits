import React from 'react';
import { Database } from 'lucide-react';
import { SkeletonCard } from '../../components/Loader';

export default function ProjectsPage({ projects, isLoading, onSelectProject, onCreateProject }) {
  const handleCreate = () => {
    // We will keep the prompt for simplicity, as confirmed in the plan.
    const name = prompt("Enter project name:");
    if (name) {
      onCreateProject(name);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      <section className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: '20px' }}>Registered Software Assets</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>
          
          {isLoading ? (
            Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)
          ) : (
            <>
              {projects.map(p => (
                <div 
                  key={p.id} 
                  className="glass-panel" 
                  style={{ padding: '24px', cursor: 'pointer', '&:hover': { borderColor: 'var(--primary)' } }} 
                  onClick={() => onSelectProject(p.id)}
                >
                  <h4 style={{ fontSize: '1.2rem', marginBottom: '8px' }}>{p.name}</h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>{p.description}</p>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    <span>Scanned: {p.latest_scan_status}</span>
                    <span>Risk Rating: {p.risk_score}/100</span>
                  </div>
                </div>
              ))}
              
              {/* Add new project card */}
              <div 
                className="glass-panel" 
                style={{ padding: '24px', borderStyle: 'dashed', borderColor: 'var(--primary)', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: '12px' }}
              >
                <Database size={32} color="var(--primary)" />
                <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>Create New Project Container</span>
                <button className="btn-primary" onClick={handleCreate} style={{ padding: '6px 12px', fontSize: '0.8rem' }}>
                  Create
                </button>
              </div>
            </>
          )}
        </div>
      </section>
    </div>
  );
}
