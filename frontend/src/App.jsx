import React, { useEffect } from 'react';
import { useLocalStorage } from './hooks/useLocalStorage';
import { usePlatformData } from './hooks/usePlatformData';
import { API_BASE } from './constants/mock';

// Components
import Sidebar from './components/Sidebar';
import PageHeader from './components/PageHeader';

// Features
import DashboardPage from './features/dashboard/DashboardPage';
import ProjectsPage from './features/projects/ProjectsPage';
import ProjectDetail from './features/projects/ProjectDetail';
import TicketsPage from './features/tickets/TicketsPage';
import PoliciesPage from './features/policies/PoliciesPage';
import AuditPage from './features/audit/AuditPage';
import VulnerabilitiesPage from './features/vulnerabilities/VulnerabilitiesPage';

const getRiskBadgeClass = (riskLevel) => {
  if (riskLevel === 'CRITICAL') return 'badge-critical';
  if (riskLevel === 'HIGH') return 'badge-high';
  return 'badge-low';
};

const getTicketStatusBadgeStyle = (status) => {
  if (status === 'OPEN') {
    return {
      background: 'rgba(239, 68, 68, 0.1)',
      color: 'var(--critical)'
    };
  }
  if (status === 'IN_PROGRESS') {
    return {
      background: 'rgba(234, 179, 8, 0.1)',
      color: 'var(--medium)'
    };
  }
  return {
    background: 'rgba(16, 185, 129, 0.1)',
    color: 'var(--low)'
  };
};

function AuthScreen({
  authMode, setAuthMode,
  authUsername, setAuthUsername,
  authPassword, setAuthPassword,
  authEmail, setAuthEmail,
  authRole, setAuthRole,
  authError, setAuthError,
  handleLogin, handleRegister,
  setIsOfflineMode, setProjects, setTickets, setAuditLogs, setPolicies,
  MOCK_PROJECTS, MOCK_TICKETS, MOCK_AUDIT, MOCK_POLICIES
}) {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#ffffff', color: 'var(--text-primary)', padding: '20px', fontFamily: 'system-ui, sans-serif' }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '420px', padding: '32px', background: 'var(--bg-card)', border: '1px solid rgba(0,0,0, 0.08)', display: 'flex', flexDirection: 'column', gap: '24px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.8), 0 10px 10px -5px rgba(0, 0, 0, 0.8)' }}>
        <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Shield size={36} color="var(--primary)" />
            <h2 style={{ fontSize: '1.8rem', fontWeight: 800 }}>SBOMGuard AI</h2>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {authMode === "login" ? "Sign in to manage supply chain security" : "Register a new compliance account"}
          </p>
        </div>

        {authError && (
          <div style={{ padding: '10px 14px', borderRadius: '6px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--critical)', color: 'var(--critical)', fontSize: '0.85rem' }}>
            {authError}
          </div>
        )}

        <form onSubmit={authMode === "login" ? handleLogin : handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label htmlFor="auth-username-input" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Username</label>
            <input 
              id="auth-username-input"
              type="text" 
              required
              placeholder="Enter username" 
              value={authUsername}
              onChange={(e) => setAuthUsername(e.target.value)}
              style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
            />
          </div>

          {authMode === "register" && (
            <div>
              <label htmlFor="auth-email-input" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Email Address</label>
              <input 
                id="auth-email-input"
                type="email" 
                placeholder="Enter email (optional)" 
                value={authEmail}
                onChange={(e) => setAuthEmail(e.target.value)}
                style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
              />
            </div>
          )}

          <div>
            <label htmlFor="auth-password-input" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Password</label>
            <input 
              id="auth-password-input"
              type="password" 
              required
              placeholder="Enter password" 
              value={authPassword}
              onChange={(e) => setAuthPassword(e.target.value)}
              style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
            />
          </div>

          {authMode === "register" && (
            <div>
              <label htmlFor="auth-role-select" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Select Role</label>
              <select 
                id="auth-role-select"
                value={authRole}
                onChange={(e) => setAuthRole(e.target.value)}
                style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#ffffff', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
              >
                <option value="DEVELOPER">DEVELOPER (Scan, View Policies, Tickets)</option>
                <option value="VIEWER">VIEWER (View Dashboard only)</option>
              </select>
            </div>
          )}

          <button type="submit" className="btn-primary" style={{ padding: '12px', width: '100%', justifyContent: 'center', marginTop: '8px' }}>
            {authMode === "login" ? "Sign In" : "Register Account"}
          </button>
        </form>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', alignItems: 'center', fontSize: '0.85rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>
            {authMode === "login" ? "Don't have an account?" : "Already have an account?"}
            <button 
              type="button" 
              onClick={() => {
                setAuthMode(authMode === "login" ? "register" : "login");
                setAuthError("");
              }} 
              style={{ background: 'none', border: 'none', color: 'var(--primary)', fontWeight: 600, cursor: 'pointer', marginLeft: '6px', padding: 0 }}
            >
              {authMode === "login" ? "Create one" : "Sign in here"}
            </button>
          </span>

          <span style={{ color: 'var(--text-muted)' }}>or</span>

          <button 
            type="button"
            className="btn-secondary" 
            onClick={() => {
              setIsOfflineMode(true);
              setProjects(MOCK_PROJECTS);
              setTickets(MOCK_TICKETS);
              setAuditLogs(MOCK_AUDIT);
              setPolicies(MOCK_POLICIES);
            }}
            style={{ width: '100%', justifyContent: 'center', padding: '10px', borderRadius: '6px' }}
          >
            Enter Offline Demo Mode
          </button>
        </div>
      </div>
    </div>
  );
}

function DashboardTab({ stats, projects, getRiskBadgeClass, setSelectedProjectId, setActiveTab }) {
  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      <div className="metrics-grid">
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ padding: '16px', borderRadius: '12px', background: 'rgba(99, 102, 241, 0.1)', border: '1px solid rgba(99, 102, 241, 0.2)' }}>
            <Database size={28} color="var(--primary)" />
          </div>
          <div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Scanned Projects</span>
            <h3 style={{ fontSize: '1.8rem', marginTop: '4px' }}>{stats.totalProjects}</h3>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ padding: '16px', borderRadius: '12px', background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.2)' }}>
            <Layers size={28} color="var(--info)" />
          </div>
          <div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Analyzed Dependencies</span>
            <h3 style={{ fontSize: '1.8rem', marginTop: '4px' }}>{stats.totalDeps}</h3>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ padding: '16px', borderRadius: '12px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
            <AlertTriangle size={28} color="var(--critical)" />
          </div>
          <div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Unresolved Vulnerabilities</span>
            <h3 style={{ fontSize: '1.8rem', marginTop: '4px', color: stats.totalCritical > 0 ? 'var(--critical)' : 'inherit' }}>
              {stats.totalCritical} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>Critical / {stats.totalHigh} High</span>
            </h3>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ padding: '16px', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
            <Activity size={28} color="var(--low)" />
          </div>
          <div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Avg SBOM Quality Score</span>
            <h3 style={{ fontSize: '1.8rem', marginTop: '4px', color: 'var(--low)' }}>{stats.avgQuality}%</h3>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '24px' }}>
        <section className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '1.1rem', marginBottom: '20px' }}>Historical SBOM Completeness & Quality</h3>
          <div style={{ width: '100%', height: '240px', display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', padding: '10px 20px', borderBottom: '1px solid var(--border-color)', position: 'relative' }}>
            <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
              <line x1="0" y1="20%" x2="100%" y2="20%" stroke="rgba(0,0,0,0.03)" strokeWidth="1" />
              <line x1="0" y1="50%" x2="100%" y2="50%" stroke="rgba(0,0,0,0.03)" strokeWidth="1" />
              <line x1="0" y1="80%" x2="100%" y2="80%" stroke="rgba(0,0,0,0.03)" strokeWidth="1" />
            </svg>
            
            <svg viewBox="0 0 500 200" style={{ width: '100%', height: '100%' }}>
              <defs>
                <linearGradient id="gradient-area" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#6366f1" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#6366f1" stopOpacity="0.0" />
                </linearGradient>
              </defs>
              <path 
                d="M 50 140 Q 150 90 250 80 T 450 40 L 450 200 L 50 200 Z" 
                fill="url(#gradient-area)" 
              />
              <path 
                d="M 50 140 Q 150 90 250 80 T 450 40" 
                fill="none" 
                stroke="#6366f1" 
                strokeWidth="4" 
                strokeLinecap="round"
              />
              <circle cx="50" cy="140" r="5" fill="#ffffff" stroke="#6366f1" strokeWidth="2" />
              <circle cx="180" cy="115" r="5" fill="#ffffff" stroke="#6366f1" strokeWidth="2" />
              <circle cx="310" cy="75" r="5" fill="#ffffff" stroke="#6366f1" strokeWidth="2" />
              <circle cx="450" cy="40" r="5" fill="#ffffff" stroke="#6366f1" strokeWidth="2" />
              
              <text x="40" y="165" fill="var(--text-muted)" fontSize="10">Scan v1 (70%)</text>
              <text x="170" y="140" fill="var(--text-muted)" fontSize="10">Scan v2 (78%)</text>
              <text x="300" y="98" fill="var(--text-muted)" fontSize="10">Scan v3 (85%)</text>
              <text x="410" y="25" fill="var(--low)" fontSize="10" fontWeight="bold">Scan v4 (94%)</text>
            </svg>
          </div>
        </section>

        <section className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <h3 style={{ fontSize: '1.1rem' }}>Active Risk Disclosures</h3>
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '160px', position: 'relative' }}>
            <svg viewBox="0 0 36 36" style={{ width: '130px', height: '130px' }}>
              <circle cx="18" cy="18" r="15.915" fill="none" stroke="rgba(0,0,0,0.05)" strokeWidth="3" />
              <circle cx="18" cy="18" r="15.915" fill="none" stroke="var(--critical)" strokeWidth="3.2" 
                strokeDasharray="20 80" strokeDashoffset="25" 
              />
              <circle cx="18" cy="18" r="15.915" fill="none" stroke="var(--high)" strokeWidth="3.2" 
                strokeDasharray="30 70" strokeDashoffset="5" 
              />
              <circle cx="18" cy="18" r="15.915" fill="none" stroke="var(--medium)" strokeWidth="3.2" 
                strokeDasharray="15 85" strokeDashoffset="75" 
              />
              <circle cx="18" cy="18" r="15.915" fill="none" stroke="var(--low)" strokeWidth="3.2" 
                strokeDasharray="35 65" strokeDashoffset="90" 
              />
            </svg>
            <div style={{ position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span style={{ fontSize: '1.6rem', fontWeight: 800 }}>10</span>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>VULNS</span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.8rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: 'var(--critical)' }} />
              <span>Critical: 2</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: 'var(--high)' }} />
              <span>High: 3</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: 'var(--medium)' }} />
              <span>Medium: 1</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: 'var(--low)' }} />
              <span>Low: 4</span>
            </div>
          </div>
        </section>
      </div>

      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ fontSize: '1.1rem' }}>Active Projects Monitoring</h3>
          <button type="button" className="btn-primary" onClick={() => setActiveTab("projects")}>
            Register & Scan <ArrowRight size={16} />
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
          {projects.map(p => (
            <div key={p.id} className="glass-panel" style={{ padding: '20px', background: 'rgba(0,0,0,0.01)', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <h4 style={{ fontSize: '1.1rem', fontWeight: 700 }}>{p.name}</h4>
                <span className={`badge ${getRiskBadgeClass(p.risk_level)}`}>{p.risk_level} RISK</span>
              </div>
              
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', height: '40px', overflow: 'hidden' }}>{p.description}</p>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Vulnerabilities: </span>
                  <span style={{ fontWeight: 700, color: p.vulnerability_count > 0 ? 'var(--critical)' : 'inherit' }}>{p.vulnerability_count}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Quality: </span>
                  <span style={{ fontWeight: 700, color: 'var(--low)' }}>{p.quality_score}%</span>
                </div>
                <button 
                  type="button"
                  className="btn-secondary" 
                  onClick={() => { setSelectedProjectId(p.id); setActiveTab("projects"); }}
                  style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                >
                  Inspect SBOM
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function AuditLogsTab({ auditLogs }) {
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
            {auditLogs.map((l, i) => (
              <tr key={l.id || `${l.timestamp}-${l.action}-${i}`} style={{ borderBottom: '1px solid var(--border-color)' }}>
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function App() {
  // Global Navigation State
  const [activeTab, setActiveTab] = useLocalStorage('active_tab', 'dashboard');
  const [selectedProjectId, setSelectedProjectId] = useLocalStorage('selected_project_id', null);

  // Global Platform Data Hook (replaces all the fetch useEffects)
  const {
    isLoading,
    isOfflineMode,
    projects, setProjects,
    tickets, setTickets,
    auditLogs, setAuditLogs,
    policies, setPolicies,
    loadPlatformData,
  } = usePlatformData();

  // Load platform data on first mount
  useEffect(() => {
    loadPlatformData();
  }, [loadPlatformData]);

  // Handlers that update global platform state
  const handleCreatePolicy = (policy) => {
    // Optimistic mock update for demo
    const p = { id: Date.now(), ...policy, is_active: true };
    setPolicies(prev => [...prev, p]);
    setAuditLogs(prev => [
      { timestamp: new Date().toISOString(), username: "admin", action: "create_policy", details: `Created policy '${policy.name}'`, ip_address: "127.0.0.1" },
      ...prev
    ]);
  };

  const handleTogglePolicy = (pId, currentStatus) => {
    setPolicies(prev => prev.map(p => p.id === pId ? { ...p, is_active: !currentStatus } : p));
  };

  const handleUpdateTicketStatus = (ticketId, currentStatus) => {
    const nextStatus = currentStatus === "OPEN" ? "IN_PROGRESS" : "RESOLVED";
    setTickets(prev => prev.map(t => t.ticket_id === ticketId ? { ...t, status: nextStatus } : t));
    setAuditLogs(prev => [
      { timestamp: new Date().toISOString(), username: "admin", action: "update_ticket", details: `Updated ticket ${ticketId} status to ${nextStatus}`, ip_address: "127.0.0.1" },
      ...prev
    ]);
  };

  const handleImportProject = async (data) => {
    try {
      if (isOfflineMode) {
        // Mock fallback for demo
        const newProj = { id: Date.now(), name: data.project.name, description: data.project.description, created_at: new Date().toISOString(), latest_scan_status: "PENDING", vulnerability_count: 0, risk_score: 0, risk_level: "LOW", quality_score: 100 };
        setProjects(prev => [...prev, newProj]);
        setSelectedProjectId(newProj.id);
        return;
      }

      // 1. Create Project Shell
      const projRes = await fetch(`${API_BASE}/api/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data.project)
      });
      if (!projRes.ok) throw new Error(await projRes.text());
      const project = await projRes.json();
      
      // 2. Trigger appropriate scan API
      if (data.type === 'github') {
        const scanRes = await fetch(`${API_BASE}/api/scans/github`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            project_id: project.id,
            ...data.github
          })
        });
        if (!scanRes.ok) throw new Error(await scanRes.text());
      } else if (data.type === 'zip') {
        const formData = new FormData();
        formData.append('project_id', project.id);
        formData.append('file', data.file);
        
        const scanRes = await fetch(`${API_BASE}/api/scans/upload`, {
          method: 'POST',
          body: formData
        });
        if (!scanRes.ok) throw new Error(await scanRes.text());
      }
      
      // 3. Update UI
      loadPlatformData(); // refresh projects list
      setSelectedProjectId(project.id); // navigate to Project Details page
      
    } catch (e) {
      alert(`Failed to import project: ${e.message}`);
    }
  };

  const handleDeleteProject = async (projectId) => {
    if (!window.confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      return;
    }
    try {
      if (isOfflineMode) {
        setProjects(prev => prev.filter(p => p.id !== projectId));
        return;
      }
      
      const res = await fetch(`${API_BASE}/api/projects/${projectId}`, {
        method: 'DELETE',
      });
      
      if (!res.ok) {
        throw new Error(await res.text());
      }
      
      loadPlatformData();
      
    } catch (e) {
      alert(`Failed to delete project: ${e.message}`);
    }
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Sidebar 
        activeTab={activeTab} 
        onTabChange={(tab) => {
          setActiveTab(tab);
          if (tab === 'dashboard') setSelectedProjectId(null);
        }}
        isOfflineMode={isOfflineMode}
        onSync={loadPlatformData}
      />

      <main style={{ flex: 1, padding: '40px', overflowY: 'auto', maxHeight: '100vh', display: 'flex', flexDirection: 'column', gap: '32px' }}>
        <PageHeader />

        {activeTab === 'dashboard' && (
          <DashboardPage 
            projects={projects} 
            tickets={tickets} 
            isLoading={isLoading} 
            isOfflineMode={isOfflineMode}
            onNavigate={setActiveTab}
            onSelectProject={setSelectedProjectId}
          />
        )}

        {activeTab === 'projects' && !selectedProjectId && (
          <ProjectsPage 
            projects={projects} 
            isLoading={isLoading}
            onSelectProject={setSelectedProjectId}
            onImportProject={handleImportProject}
            onDeleteProject={handleDeleteProject}
          />
        )}

        {activeTab === 'projects' && selectedProjectId && (
          <ProjectDetail 
            projectId={selectedProjectId}
            isOfflineMode={isOfflineMode}
            onBack={() => setSelectedProjectId(null)}
            onScanComplete={loadPlatformData} // Refresh global stats after scan
          />
        )}

        {activeTab === 'vulnerabilities' && (
          <VulnerabilitiesPage isOfflineMode={isOfflineMode} />
        )}

        {activeTab === 'tickets' && (
          <TicketsPage 
            tickets={tickets} 
            isLoading={isLoading} 
            onUpdateTicketStatus={handleUpdateTicketStatus}
          />
        )}

        {activeTab === 'policies' && (
          <PoliciesPage 
            policies={policies}
            onTogglePolicy={handleTogglePolicy}
            onCreatePolicy={handleCreatePolicy}
          />
        )}

        {activeTab === 'audit' && (
          <AuditPage 
            auditLogs={auditLogs}
            isLoading={isLoading}
          />
        )}
      </main>
    </div>
  );
}
