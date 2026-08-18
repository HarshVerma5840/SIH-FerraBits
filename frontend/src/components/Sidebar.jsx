import React from 'react';
import {
  Activity, Database, AlertTriangle, FileText,
  Sliders, RefreshCw, Shield, Bug
} from 'lucide-react';

const NAV_ITEMS = [
  { key: 'dashboard',      icon: Activity,       label: 'Dashboard'         },
  { key: 'projects',       icon: Database,       label: 'Scan & Projects'   },
  { key: 'vulnerabilities',icon: Bug,            label: 'Vulnerabilities'   },
  { key: 'tickets',        icon: AlertTriangle,  label: 'Remediation Center'},
  { key: 'policies',       icon: Sliders,        label: 'Policy Studio'     },
  { key: 'audit',          icon: FileText,       label: 'Audit Logs'        },
];

export default function Sidebar({ activeTab, onTabChange, isOfflineMode, onSync }) {
  return (
    <aside
      className="glass-panel"
      style={{
        width: '260px', padding: '24px 16px',
        display: 'flex', flexDirection: 'column', gap: '32px',
        borderRight: '1px solid var(--border-color)',
        borderRadius: '0', position: 'sticky', top: 0, height: '100vh',
        overflowY: 'auto', flexShrink: 0,
      }}
    >
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', paddingLeft: '8px' }}>
        <div style={{
          background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
          padding: '8px', borderRadius: '10px',
          display: 'flex', justifyContent: 'center', alignItems: 'center',
        }}>
          <Shield size={24} color="white" />
        </div>
        <div>
          <h2 style={{
            fontSize: '1.2rem', fontWeight: 800,
            background: 'linear-gradient(to right, #ffffff, #9ca3af)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>SBOMGuard AI</h2>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.05em' }}>
            COMPLIANCE SYSTEM
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {NAV_ITEMS.map(({ key, icon: Icon, label }) => {
          const isActive = activeTab === key;
          return (
            <button
              key={key}
              className="btn-secondary"
              onClick={() => onTabChange(key)}
              style={{
                width: '100%', justifyContent: 'flex-start',
                background: isActive ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
                borderColor: isActive ? 'var(--primary)' : 'transparent',
              }}
            >
              <Icon size={18} color={isActive ? '#818cf8' : '#9ca3af'} />
              {label}
            </button>
          );
        })}
      </nav>

      {/* Connection status */}
      <div style={{
        marginTop: 'auto', padding: '16px',
        background: 'rgba(255, 255, 255, 0.03)',
        borderRadius: '12px', border: '1px solid var(--border-color)',
        display: 'flex', flexDirection: 'column', gap: '8px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: isOfflineMode ? 'var(--high)' : 'var(--low)',
          }} />
          <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>
            {isOfflineMode ? 'Offline Demo Mode' : 'Connected to Server'}
          </span>
        </div>
        <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          {isOfflineMode
            ? 'Local server unreachable. Operating on mock engine dataset.'
            : 'FastAPI backend connection active. All ML predictions live.'}
        </p>
        <button
          className="btn-secondary"
          onClick={onSync}
          style={{ padding: '6px', fontSize: '0.75rem', width: '100%', justifyContent: 'center' }}
        >
          <RefreshCw size={12} /> Sync Database
        </button>
      </div>
    </aside>
  );
}
