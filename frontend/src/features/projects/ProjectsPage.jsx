import React, { useState } from 'react';
import { Database, UploadCloud, Trash2 } from 'lucide-react';
import { SkeletonCard } from '../../components/Loader';
import ImportProjectModal from './ImportProjectModal';

export default function ProjectsPage({ projects, isLoading, onSelectProject, onImportProject, onDeleteProject }) {
  const [isModalOpen, setIsModalOpen] = useState(false);

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
                  className="glass-panel project-card" 
                  style={{ padding: '24px', cursor: 'pointer', position: 'relative' }} 
                  onClick={() => onSelectProject(p.id)}
                >
                  <button 
                    style={{ position: 'absolute', top: '16px', right: '16px', background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      onDeleteProject && onDeleteProject(p.id);
                    }}
                    title="Delete Project"
                    onMouseEnter={(e) => e.currentTarget.style.color = 'var(--critical)'}
                    onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
                  >
                    <Trash2 size={18} />
                  </button>
                  <h4 style={{ fontSize: '1.2rem', marginBottom: '8px', paddingRight: '24px' }}>{p.name}</h4>
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
                style={{ padding: '24px', borderStyle: 'dashed', borderColor: 'var(--primary)', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
                onClick={() => setIsModalOpen(true)}
              >
                <UploadCloud size={32} color="var(--primary)" />
                <span style={{ fontSize: '1rem', fontWeight: 600 }}>Import Software Asset</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>GitHub Repository or ZIP Upload</span>
              </div>
            </>
          )}
        </div>
      </section>

      <ImportProjectModal 
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onImport={(data) => {
          setIsModalOpen(false);
          onImportProject(data);
        }}
      />
    </div>
  );
}
