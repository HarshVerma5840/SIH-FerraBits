<<<<<<< HEAD
import React, { useEffect } from 'react';
import { useLocalStorage } from './hooks/useLocalStorage';
import { usePlatformData } from './hooks/usePlatformData';
=======
import React, { useState, useEffect } from 'react';
import { 
  Shield, Database, AlertTriangle, FileText, Activity, 
  GitBranch, RefreshCw, Upload, XCircle, Search, 
  Sliders, ArrowRight, Layers, Download, Check, HelpCircle
} from 'lucide-react';
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92

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
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#0b0f19', color: 'white', padding: '20px', fontFamily: 'system-ui, sans-serif' }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '420px', padding: '32px', background: 'rgba(15, 23, 42, 0.45)', border: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', flexDirection: 'column', gap: '24px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.8), 0 10px 10px -5px rgba(0, 0, 0, 0.8)' }}>
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
              style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#05070c', border: '1px solid var(--border-color)', color: 'white' }}
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
                style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#05070c', border: '1px solid var(--border-color)', color: 'white' }}
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
              style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', background: '#05070c', border: '1px solid var(--border-color)', color: 'white' }}
            />
          </div>

          {authMode === "register" && (
            <div>
              <label htmlFor="auth-role-select" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Select Role</label>
              <select 
                id="auth-role-select"
                value={authRole}
                onChange={(e) => setAuthRole(e.target.value)}
                style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#05070c', border: '1px solid var(--border-color)', color: 'white' }}
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
              <line x1="0" y1="20%" x2="100%" y2="20%" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
              <line x1="0" y1="50%" x2="100%" y2="50%" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
              <line x1="0" y1="80%" x2="100%" y2="80%" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
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
              <circle cx="18" cy="18" r="15.915" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="3" />
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
            <div key={p.id} className="glass-panel" style={{ padding: '20px', background: 'rgba(255,255,255,0.01)', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
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
            <tr style={{ background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border-color)' }}>
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
<<<<<<< HEAD
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
=======
  const [token, setToken] = useState(localStorage.getItem("sbomguard_token") || "");
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authEmail, setAuthEmail] = useState("");
  const [authRole, setAuthRole] = useState("DEVELOPER");
  const [authError, setAuthError] = useState("");

  const [activeTab, setActiveTab] = useState("dashboard");
  const [projects, setProjects] = useState([]);
  const [selectedProjectId, setSelectedProjectId] = useState(null);
  const [selectedProject, setSelectedProject] = useState(null);
  const [tickets, setTickets] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [policies, setPolicies] = useState([]);

  const getAuthHeaders = () => {
    return token ? { "Authorization": `Bearer ${token}` } : {};
  };

  const getHeaders = (isJson = false) => {
    const headers = { ...getAuthHeaders() };
    if (isJson) {
      headers["Content-Type"] = "application/json";
    }
    return headers;
  };

  useEffect(() => {
    const verifyToken = async () => {
      if (token) {
        try {
          const res = await fetch(`${API_BASE}/auth/me`, {
            headers: { "Authorization": `Bearer ${token}` }
          });
          if (res.ok) {
            const userData = await res.json();
            setUser(userData);
            setIsOfflineMode(false);
          } else {
            localStorage.removeItem("sbomguard_token");
            setToken("");
            setUser(null);
          }
        } catch (err) {
          console.error("Auth server offline. Operating token in fallback mode.", err);
          setUser({ username: "admin", role: "ADMIN" });
        }
      }
    };
    verifyToken();
  }, [token]);

  useEffect(() => {
    if (token || isOfflineMode) {
      loadPlatformData();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, isOfflineMode]);

  const handleRegister = async (e) => {
    e.preventDefault();
    setAuthError("");
    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: authUsername,
          password: authPassword,
          email: authEmail,
          role: authRole
        })
      });
      if (res.ok) {
        setAuthMode("login");
        setAuthError("Registration successful! Please login.");
      } else {
        const data = await res.json();
        setAuthError(data.detail || "Registration failed");
      }
    } catch (err) {
      console.error("Auth register connection error", err);
      setAuthError("Could not connect to auth service");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError("");
    try {
      const formData = new URLSearchParams();
      formData.append("username", authUsername);
      formData.append("password", authPassword);

      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData.toString()
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem("sbomguard_token", data.access_token);
        setToken(data.access_token);
        setUser({ username: data.username, role: data.role });
        setIsOfflineMode(false);
      } else {
        const data = await res.json();
        setAuthError(data.detail || "Invalid credentials");
      }
    } catch (err) {
      console.error("Auth login connection error", err);
      setAuthError("Could not connect to auth service");
    }
  };

  const handleDownloadReport = async (endpoint, filename) => {
    if (isOfflineMode) {
      const dummyContent = endpoint.includes("csv") 
        ? "Mock,CSV,Data\nProject," + selectedProject?.name + ",1"
        : JSON.stringify({ mock: true, project: selectedProject?.name }, null, 2);
      const blob = new Blob([dummyContent], { type: endpoint.includes("csv") ? "text/csv" : "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(url);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        headers: getAuthHeaders()
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
        window.URL.revokeObjectURL(url);
      } else {
        alert("Failed to download report: status " + res.status);
      }
    } catch (err) {
      alert("Failed to connect to report endpoint: " + err.message);
    }
  };
  
  // Scans management state
  const [localScanPath, setLocalScanPath] = useState("");
  const [scanLogs, setScanLogs] = useState("");
  const [scanProgress, setScanProgress] = useState(false);
  const [scanMessage, setScanMessage] = useState("");

  // Projects detail subtabs
  const [detailSubtab, setDetailSubtab] = useState("sbom");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEcosystem, setSelectedEcosystem] = useState("all");
  const [selectedRisk, setSelectedRisk] = useState("all");
  
  // Expanded row tracking for SBOM list
  const [expandedCompId, setExpandedCompId] = useState(null);
  const [vexStatus, setVexStatus] = useState("UNDER_INVESTIGATION");
  const [vexJustification, setVexJustification] = useState("");
  const [vexFeedback, setVexFeedback] = useState("");

  // Version history & diff
  const [selectedVersionBase, setSelectedVersionBase] = useState("");
  const [selectedVersionHead, setSelectedVersionHead] = useState("");
  const [versionHistory, setVersionHistory] = useState([]);
  const [diffResult, setDiffResult] = useState(null);

  // What-if simulator state
  const [whatIfPurl, setWhatIfPurl] = useState("");
  const [whatIfVersion, setWhatIfVersion] = useState("");
  const [whatIfResult, setWhatIfResult] = useState(null);

  // Policy creation state
  const [newPolicyName, setNewPolicyName] = useState("");
  const [newPolicyType, setNewPolicyType] = useState("CVSS_THRESHOLD");
  const [newPolicyCond, setNewPolicyCond] = useState(">= 9.0");
  const [newPolicyAction, setNewPolicyAction] = useState("BLOCK");

  // Visual graph selected node / blast radius
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);
  const [graphBlastRadius, setGraphBlastRadius] = useState(null);

  // Mode state (Server vs Mock Offline)
  const [isOfflineMode, setIsOfflineMode] = useState(false);

  // Fetch base platform records
  const loadPlatformData = async () => {
    try {
      // Test backend availability
      const testReq = await fetch(`${API_BASE}/`);
      if (testReq.ok) {
        setIsOfflineMode(false);
        
        // Fetch projects
        const projRes = await fetch(`${API_BASE}/api/projects`, { headers: getAuthHeaders() });
        if (projRes.ok) setProjects(await projRes.json());
        
        // Fetch tickets
        const tickRes = await fetch(`${API_BASE}/api/tickets`, { headers: getAuthHeaders() });
        if (tickRes.ok) setTickets(await tickRes.json());
        
        // Fetch audit logs
        const auditRes = await fetch(`${API_BASE}/api/audit-logs`, { headers: getAuthHeaders() });
        if (auditRes.ok) setAuditLogs(await auditRes.json());
        
        // Fetch policies
        const polRes = await fetch(`${API_BASE}/api/policies`, { headers: getAuthHeaders() });
        if (polRes.ok) setPolicies(await polRes.json());
      } else {
        throw new Error("Server not responding");
      }
    } catch (e) {
      console.error("Server offline, booting in fully-functional Mock Demo mode.", e);
      setIsOfflineMode(true);
      setProjects(MOCK_PROJECTS);
      setTickets(MOCK_TICKETS);
      setAuditLogs(MOCK_AUDIT);
      setPolicies(MOCK_POLICIES);
    }
  };
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92

  // Load platform data on first mount
  useEffect(() => {
<<<<<<< HEAD
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
=======
    if (selectedProjectId) {
      fetchProjectDetails(selectedProjectId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProjectId]);

  const fetchProjectDetails = async (projId) => {
    if (isOfflineMode) {
      const match = MOCK_PROJECTS.find(p => p.id === projId);
      if (match) {
        setSelectedProject({
          ...match,
          components: MOCK_COMPONENTS_1,
          vulnerabilities: MOCK_COMPONENTS_1.flatMap(c => c.vulnerabilities),
          anomalies: MOCK_COMPONENTS_1.filter(c => c.anomaly_score > 40).map(c => ({
            purl: c.purl,
            score: c.anomaly_score,
            probability: c.anomaly_score / 100,
            classification: c.anomaly_score > 60 ? "SUSPICIOUS" : "NORMAL",
            indicators: c.name.includes("malicious") ? ["obfuscation", "install scripts", "network socket calls"] : ["minor anomalies"]
          })),
          remediations: MOCK_COMPONENTS_1.filter(c => c.vulnerabilities.length > 0).map(c => ({
            purl: c.purl,
            current_version: c.version,
            recommended_version: c.version.startsWith("4") ? "4.17.21" : "2.15.0",
            upgrade_impact: "Minor logic modifications. Review downstream API changes."
          }))
        });
        setVersionHistory([
          { version_number: 2, sbom_id: 200, created_at: "2026-08-17T09:00:00Z", components_count: 5, scan_id: 1, scan_triggered_by: "admin" },
          { version_number: 1, sbom_id: 100, created_at: "2026-08-16T12:00:00Z", components_count: 4, scan_id: 2, scan_triggered_by: "system" }
        ]);
      }
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/projects/${projId}`, { headers: getAuthHeaders() });
        if (r.ok) {
          const detail = await r.json();
          setSelectedProject(detail);
        }
        
        const rHistory = await fetch(`${API_BASE}/api/projects/${projId}/history`, { headers: getAuthHeaders() });
        if (rHistory.ok) {
          setVersionHistory(await rHistory.json());
        }
      } catch (e) {
        console.error("Failed to load project details", e);
      }
    }
  };

  // Trigger scan
  const handleTriggerScan = async (e) => {
    e.preventDefault();
    if (!localScanPath) {
      alert("Please enter a scan directory path.");
      return;
    }
    
    setScanProgress(true);
    setScanMessage("Contacting scanner agent...");
    setScanLogs("Initiating scan...\n");
    
    if (isOfflineMode) {
      // Mock scanning pipeline sequence
      setTimeout(() => {
        setScanLogs(prev => prev + "[2026-08-17T09:20:00Z] Scanning local directories for manifest files...\n");
      }, 500);
      setTimeout(() => {
        setScanLogs(prev => prev + "[2026-08-17T09:20:01Z] Found NPM package.json and Maven pom.xml. Compiling dependencies...\n");
      }, 1200);
      setTimeout(() => {
        setScanLogs(prev => prev + "[2026-08-17T09:20:02Z] Running AI anomaly classification (Isolation Forest and Random Forest)...\n");
      }, 2000);
      setTimeout(() => {
        setScanLogs(prev => prev + "[2026-08-17T09:20:03Z] Correlating vulnerabilities. Flagged 5 CVE findings.\n");
      }, 2800);
      setTimeout(() => {
        setScanLogs(prev => prev + "[2026-08-17T09:20:04Z] SBOM Signing generated. Policy check completed: BLOCKED (Exit Code 2).\n");
        setScanProgress(false);
        setScanMessage("Scan Completed. Corporate compliance rules trigger BLOCK: 1 Critical RCE found.");
        
        // Refresh project data
        fetchProjectDetails(selectedProjectId);
        
        // Append audit log
        setAuditLogs(prev => [
          { timestamp: new Date().toISOString(), username: "admin", action: "scan_completed", details: `Completed scan for local directory: ${localScanPath}`, ip_address: "127.0.0.1" },
          ...prev
        ]);
      }, 3500);
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/scans/local`, {
          method: "POST",
          headers: getHeaders(true),
          body: JSON.stringify({
            project_id: selectedProjectId,
            directory_path: localScanPath
          })
        });
        if (r.ok) {
          const res = await r.json();
          const scanId = res.scan_id;
          setScanMessage(`Scan initiated. Scan ID: ${scanId}. Polling logs...`);
          
          // Poll logs & status
          const interval = setInterval(async () => {
            const statusReq = await fetch(`${API_BASE}/api/scans/${scanId}/status`, { headers: getAuthHeaders() });
            const logsReq = await fetch(`${API_BASE}/api/scans/${scanId}/logs`, { headers: getAuthHeaders() });
            
            if (statusReq.ok && logsReq.ok) {
              const statusData = await statusReq.json();
              const logsData = await logsReq.json();
              
              setScanLogs(logsData.logs);
              
              if (statusData.status === "COMPLETED") {
                clearInterval(interval);
                setScanProgress(false);
                setScanMessage("Scan completed successfully.");
                fetchProjectDetails(selectedProjectId);
                loadPlatformData();
              } else if (statusData.status === "FAILED") {
                clearInterval(interval);
                setScanProgress(false);
                setScanMessage("Scan failed. Review diagnostic logs.");
              }
            }
          }, 1500);
        } else {
          setScanProgress(false);
          const txt = await r.text();
          setScanMessage(`Error: ${txt}`);
        }
      } catch (e) {
        setScanProgress(false);
        setScanMessage(`Network error triggering scan: ${e.message}`);
      }
    }
  };

  // VEX Status updates
  const handleUpdateVex = async (e) => {
    e.preventDefault();
    if (!vexJustification) {
      alert("Please provide a VEX justification statement.");
      return;
    }
    
    setVexFeedback("Saving VEX state...");
    
    if (isOfflineMode) {
      setTimeout(() => {
        setVexFeedback("VEX status updated successfully.");
        // Find component and update explanation locally
        setSelectedProject(prev => {
          const comps = prev.components.map(c => {
            if (c.purl === expandedCompId) {
              return {
                ...c,
                explanation: `[VEX STATUS: ${vexStatus}] Reason: ${vexJustification}. (History: ${c.explanation})`
              };
            }
            return c;
          });
          return { ...prev, components: comps };
        });
        
        // Log audit event
        setAuditLogs(prev => [
          { timestamp: new Date().toISOString(), username: "admin", action: "update_vex", details: `Updated VEX status for ${expandedCompId} to ${vexStatus}`, ip_address: "127.0.0.1" },
          ...prev
        ]);
        
        setVexJustification("");
      }, 800);
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/vulnerabilities/vex`, {
          method: "PUT",
          headers: getHeaders(true),
          body: JSON.stringify({
            component_purl: expandedCompId,
            scan_id: selectedProject.latest_scan_id,
            vex_status: vexStatus,
            justification: vexJustification
          })
        });
        if (r.ok) {
          setVexFeedback("VEX status updated successfully.");
          fetchProjectDetails(selectedProjectId);
          setVexJustification("");
        } else {
          setVexFeedback("Error saving VEX status.");
        }
      } catch (err) {
        setVexFeedback(`Connection error: ${err.message}`);
      }
    }
  };

  // Compare versions
  const handleCompareVersions = async () => {
    if (!selectedVersionBase || !selectedVersionHead) {
      alert("Please select both base and head versions to compare.");
      return;
    }
    
    if (isOfflineMode) {
      setDiffResult({
        added: [
          { name: "requests", version: "2.31.0", ecosystem: "pypi", license: "Apache-2.0", type: "library" }
        ],
        removed: [],
        updated: [
          { name: "lodash", old_version: "4.17.9", new_version: "4.17.11", old_license: "MIT", new_license: "MIT" }
        ]
      });
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/diff/${selectedVersionBase}/${selectedVersionHead}`, { headers: getAuthHeaders() });
        if (r.ok) {
          setDiffResult(await r.json());
        }
      } catch (e) {
        alert("Failed to compute diff on backend: " + e.message);
      }
    }
  };

  // What-if simulator
  const handleWhatIfSimulation = async (e) => {
    e.preventDefault();
    if (!whatIfPurl || !whatIfVersion) {
      alert("Please specify both target package and version.");
      return;
    }
    
    if (isOfflineMode) {
      // Mock result
      setWhatIfResult({
        status: "SIMULATION",
        upgraded_package: whatIfPurl.split("/").pop().split("@")[0],
        target_version: whatIfVersion,
        projected_total_risk: whatIfPurl.includes("log4j") ? 65 : 85,
        projected_vulnerability_count: whatIfPurl.includes("log4j") ? 4 : 5,
        projected_critical_count: whatIfPurl.includes("log4j") ? 0 : 1,
        projected_high_count: 3
      });
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/whatif`, {
          method: "POST",
          headers: getHeaders(true),
          body: JSON.stringify({
            upgrade_purl: whatIfPurl,
            target_version: whatIfVersion
          })
        });
        if (r.ok) {
          setWhatIfResult(await r.json());
        }
      } catch (err) {
        alert("Error running simulation on backend: " + err.message);
      }
    }
  };

  // Add policy
  const handleCreatePolicy = async (e) => {
    e.preventDefault();
    if (!newPolicyName) {
      alert("Please enter a policy name.");
      return;
    }
    
    if (isOfflineMode) {
      const p = {
        id: Date.now(),
        name: newPolicyName,
        rule_type: newPolicyType,
        rule_condition: newPolicyCond,
        action: newPolicyAction,
        is_active: true
      };
      setPolicies(prev => [...prev, p]);
      setNewPolicyName("");
      
      setAuditLogs(prev => [
        { timestamp: new Date().toISOString(), username: "admin", action: "create_policy", details: `Created policy '${newPolicyName}'`, ip_address: "127.0.0.1" },
        ...prev
      ]);
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/policies`, {
          method: "POST",
          headers: getHeaders(true),
          body: JSON.stringify({
            name: newPolicyName,
            rule_type: newPolicyType,
            rule_condition: newPolicyCond,
            action: newPolicyAction
          })
        });
        if (r.ok) {
          loadPlatformData();
          setNewPolicyName("");
        }
      } catch (err) {
        alert("Failed to save policy: " + err.message);
      }
    }
  };

  // Toggle Policy status
  const handleTogglePolicy = async (pId, currentStatus) => {
    if (isOfflineMode) {
      setPolicies(prev => prev.map(p => p.id === pId ? { ...p, is_active: !currentStatus } : p));
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/policies/${pId}`, {
          method: "PUT",
          headers: getHeaders(true),
          body: JSON.stringify({
            is_active: !currentStatus
          })
        });
        if (r.ok) loadPlatformData();
      } catch (err) {
        console.error("Failed to toggle policy status", err);
      }
    }
  };

  // Toggle Ticket status
  const handleUpdateTicketStatus = async (ticketId, currentStatus) => {
    const nextStatus = currentStatus === "OPEN" ? "IN_PROGRESS" : "RESOLVED";
    if (isOfflineMode) {
      setTickets(prev => prev.map(t => t.ticket_id === ticketId ? { ...t, status: nextStatus } : t));
      
      setAuditLogs(prev => [
        { timestamp: new Date().toISOString(), username: "admin", action: "update_ticket", details: `Updated ticket ${ticketId} status to ${nextStatus}`, ip_address: "127.0.0.1" },
        ...prev
      ]);
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/tickets/${ticketId}`, {
          method: "PUT",
          headers: getHeaders(true),
          body: JSON.stringify({
            status: nextStatus
          })
        });
        if (r.ok) loadPlatformData();
      } catch (e) {
        console.error("Failed to update ticket", e);
      }
    }
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92
  };

  const handleCreateProject = (name) => {
    setProjects(prev => [
      ...prev,
      { id: Date.now(), name, description: "Custom developer codebase container.", created_at: new Date().toISOString(), latest_scan_status: "NEVER_SCANNED", vulnerability_count: 0, risk_score: 0, risk_level: "LOW", quality_score: 100 }
    ]);
  };

<<<<<<< HEAD
=======
  const stats = getDashboardStats();

  if (!token && !isOfflineMode) {
    return (
      <AuthScreen
        authMode={authMode}
        setAuthMode={setAuthMode}
        authUsername={authUsername}
        setAuthUsername={setAuthUsername}
        authPassword={authPassword}
        setAuthPassword={setAuthPassword}
        authEmail={authEmail}
        setAuthEmail={setAuthEmail}
        authRole={authRole}
        setAuthRole={setAuthRole}
        authError={authError}
        setAuthError={setAuthError}
        handleLogin={handleLogin}
        handleRegister={handleRegister}
        setIsOfflineMode={setIsOfflineMode}
        setProjects={setProjects}
        setTickets={setTickets}
        setAuditLogs={setAuditLogs}
        setPolicies={setPolicies}
        MOCK_PROJECTS={MOCK_PROJECTS}
        MOCK_TICKETS={MOCK_TICKETS}
        MOCK_AUDIT={MOCK_AUDIT}
        MOCK_POLICIES={MOCK_POLICIES}
      />
    );
  }

>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92
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

<<<<<<< HEAD
      <main style={{ flex: 1, padding: '40px', overflowY: 'auto', maxHeight: '100vh', display: 'flex', flexDirection: 'column', gap: '32px' }}>
        <PageHeader />
=======
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <button 
            type="button"
            className={`btn-secondary ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => { setActiveTab("dashboard"); setSelectedProjectId(null); }}
            style={{ width: '100%', justifyContent: 'flex-start', background: activeTab === 'dashboard' ? 'rgba(99, 102, 241, 0.15)' : 'transparent', borderColor: activeTab === 'dashboard' ? 'var(--primary)' : 'transparent' }}
          >
            <Activity size={18} color={activeTab === 'dashboard' ? '#818cf8' : '#9ca3af'} /> Dashboard
          </button>
          
          <button 
            type="button"
            className={`btn-secondary ${activeTab === 'projects' ? 'active' : ''}`}
            onClick={() => setActiveTab("projects")}
            style={{ width: '100%', justifyContent: 'flex-start', background: activeTab === 'projects' ? 'rgba(99, 102, 241, 0.15)' : 'transparent', borderColor: activeTab === 'projects' ? 'var(--primary)' : 'transparent' }}
          >
            <Database size={18} color={activeTab === 'projects' ? '#818cf8' : '#9ca3af'} /> Scan & Projects
          </button>

          <button 
            type="button"
            className={`btn-secondary ${activeTab === 'tickets' ? 'active' : ''}`}
            onClick={() => setActiveTab("tickets")}
            style={{ width: '100%', justifyContent: 'flex-start', background: activeTab === 'tickets' ? 'rgba(99, 102, 241, 0.15)' : 'transparent', borderColor: activeTab === 'tickets' ? 'var(--primary)' : 'transparent' }}
          >
            <AlertTriangle size={18} color={activeTab === 'tickets' ? '#818cf8' : '#9ca3af'} /> Remediation Center
          </button>

          <button 
            type="button"
            className={`btn-secondary ${activeTab === 'policies' ? 'active' : ''}`}
            onClick={() => setActiveTab("policies")}
            style={{ width: '100%', justifyContent: 'flex-start', background: activeTab === 'policies' ? 'rgba(99, 102, 241, 0.15)' : 'transparent', borderColor: activeTab === 'policies' ? 'var(--primary)' : 'transparent' }}
          >
            <Sliders size={18} color={activeTab === 'policies' ? '#818cf8' : '#9ca3af'} /> Policy Studio
          </button>

          <button 
            type="button"
            className={`btn-secondary ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab("audit")}
            style={{ width: '100%', justifyContent: 'flex-start', background: activeTab === 'audit' ? 'rgba(99, 102, 241, 0.15)' : 'transparent', borderColor: activeTab === 'audit' ? 'var(--primary)' : 'transparent' }}
          >
            <FileText size={18} color={activeTab === 'audit' ? '#818cf8' : '#9ca3af'} /> Audit Logs
          </button>
        </nav>

        <div style={{ marginTop: 'auto', padding: '16px', background: 'rgba(255, 255, 255, 0.03)', borderRadius: '12px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: isOfflineMode ? 'var(--high)' : 'var(--low)' }} />
            <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{isOfflineMode ? 'Offline Demo Mode' : 'Connected to Server'}</span>
          </div>
          <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            {isOfflineMode 
              ? 'Local server unreachable. Operating on mock engine dataset.' 
              : 'FastAPI backend connection active. All ML predictions live.'}
          </p>
          <button type="button" className="btn-secondary" onClick={loadPlatformData} style={{ padding: '6px', fontSize: '0.75rem', width: '100%', justifyContent: 'center' }}>
            <RefreshCw size={12} /> Sync Database
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: '40px', overflowY: 'auto', maxHeight: '100vh', display: 'flex', flexDirection: 'column', gap: '32px' }}>
        
        {/* Header Banner */}
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <span style={{ color: 'var(--primary)', fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Secure Software Supply Chain</span>
            <h1 style={{ fontSize: '2.2rem', marginTop: '4px' }}>AI Compliance & Assessment Platform</h1>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', background: 'rgba(255,255,255,0.03)', padding: '8px 16px', borderRadius: '30px', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{user?.username || 'Security Operations Center'}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Role: {user?.role || 'Administrator'}</span>
              </div>
              <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'linear-gradient(135deg, #6366f1 0%, #3b82f6 100%)', display: 'flex', justifyContent: 'center', alignItems: 'center', fontWeight: 800 }}>
                {(user?.username?.substring(0, 2) || "AD").toUpperCase()}
              </div>
            </div>
            <button 
              type="button"
              className="btn-secondary" 
              onClick={() => {
                localStorage.removeItem("sbomguard_token");
                setToken("");
                setUser(null);
                setIsOfflineMode(false);
              }}
              style={{ padding: '8px 12px', fontSize: '0.8rem', borderRadius: '20px' }}
            >
              Logout
            </button>
          </div>
        </header>
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92

        {activeTab === 'dashboard' && (
<<<<<<< HEAD
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
            onCreateProject={handleCreateProject}
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
=======
          <DashboardTab
            stats={stats}
            projects={projects}
            getRiskBadgeClass={getRiskBadgeClass}
            setSelectedProjectId={setSelectedProjectId}
            setActiveTab={setActiveTab}
          />
        )}

        {/* TAB 2: PROJECTS & SCAN */}
        {activeTab === 'projects' && (
          <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            
            {/* If no project selected, show list and creation */}
            {!selectedProjectId ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
                <section className="glass-panel" style={{ padding: '24px' }}>
                  <h3 style={{ fontSize: '1.1rem', marginBottom: '20px' }}>Registered Software Assets</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>
                    {projects.map(p => (
                      <div 
                        key={p.id} 
                        className="glass-panel" 
                        style={{ padding: '24px', cursor: 'pointer', '&:hover': { borderColor: 'var(--primary)' } }} 
                        onClick={() => setSelectedProjectId(p.id)}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            setSelectedProjectId(p.id);
                          }
                        }}
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
                    <div className="glass-panel" style={{ padding: '24px', borderStyle: 'dashed', borderColor: 'var(--primary)', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: '12px' }}>
                      <Database size={32} color="var(--primary)" />
                      <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>Create New Project Container</span>
                      <button type="button" className="btn-primary" onClick={() => {
                        const name = prompt("Enter project name:");
                        if (name) {
                          setProjects(prev => [
                            ...prev,
                            { id: Date.now(), name, description: "Custom developer codebase container.", created_at: new Date().toISOString(), latest_scan_status: "NEVER_SCANNED", vulnerability_count: 0, risk_score: 0, risk_level: "LOW", quality_score: 100 }
                          ]);
                        }
                      }} style={{ padding: '6px 12px', fontSize: '0.8rem' }}>Create</button>
                    </div>
                  </div>
                </section>
              </div>
            ) : (
              
              /* Project details page */
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <button type="button" className="btn-secondary" onClick={() => { setSelectedProjectId(null); setSelectedProject(null); }}>
                    &larr; Back to Assets
                  </button>
                  <h2 style={{ fontSize: '1.6rem' }}>{selectedProject?.name}</h2>
                  <span className={`badge ${
                    selectedProject?.risk_summary.level === 'CRITICAL' ? 'badge-critical' : 'badge-low'
                  }`}>{selectedProject?.risk_summary.level} Risk ({selectedProject?.risk_summary.score}/100)</span>
                </div>

                {/* Local scan executor */}
                <section className="glass-panel" style={{ padding: '24px' }}>
                  <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Activity size={18} /> Trigger Compliance Audit Scanning
                  </h3>
                  
                  <form onSubmit={handleTriggerScan} style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                    <label htmlFor="scan-path-input" style={{ display: 'none' }}>Local Scan Directory Path</label>
                    <input 
                      id="scan-path-input"
                      type="text" 
                      placeholder="Enter local repository absolute directory path (e.g. C:\Users\User\my-app)..." 
                      value={localScanPath}
                      onChange={(e) => setLocalScanPath(e.target.value)}
                      style={{ flex: 1, padding: '12px', borderRadius: '8px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', color: 'white' }}
                    />
                    <button type="submit" className="btn-primary" disabled={scanProgress}>
                      <Upload size={16} /> {scanProgress ? 'Scanning...' : 'Trigger Scan Engine'}
                    </button>
                  </form>
                  
                  {scanMessage && (
                    <div style={{ marginTop: '12px', padding: '8px 12px', borderRadius: '6px', background: 'rgba(255,255,255,0.05)', fontSize: '0.85rem' }}>
                      <strong>Status: </strong> {scanMessage}
                    </div>
                  )}

                  {scanLogs && (
                    <div style={{ marginTop: '16px', background: '#05070c', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: 600 }}>Diagnostic Scan Logs:</span>
                      <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#10b981', maxHeight: '180px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                        {scanLogs}
                      </pre>
                    </div>
                  )}
                </section>

                {/* Subnavigation Tabs */}
                <div style={{ display: 'flex', gap: '12px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
                  {["sbom", "graph", "compliance", "diff", "whatif", "reports"].map(tab => (
                    <button 
                      key={tab} 
                      type="button"
                      className={`btn-secondary ${detailSubtab === tab ? 'active' : ''}`}
                      onClick={() => setDetailSubtab(tab)}
                      style={{ 
                        background: detailSubtab === tab ? 'rgba(99,102,241,0.1)' : 'transparent',
                        borderColor: detailSubtab === tab ? 'var(--primary)' : 'transparent',
                        padding: '6px 14px',
                        fontSize: '0.85rem'
                      }}
                    >
                      {tab === 'sbom' && 'SBOM Catalog'}
                      {tab === 'graph' && 'Dependency attack graph'}
                      {tab === 'compliance' && 'CI/CD Compliance'}
                      {tab === 'diff' && 'History & Diffs'}
                      {tab === 'whatif' && 'What-If Risk Simulator'}
                      {tab === 'reports' && 'Executive Reports'}
                    </button>
                  ))}
                </div>

                {/* SUBTAB 1: SBOM CATALOG */}
                {detailSubtab === 'sbom' && (
                  <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <div style={{ flex: 1, position: 'relative' }}>
                        <label htmlFor="search-deps-input" style={{ display: 'none' }}>Search dependencies</label>
                        <Search size={16} style={{ position: 'absolute', left: '12px', top: '14px', color: 'var(--text-muted)' }} />
                        <input 
                          id="search-deps-input"
                          type="text" 
                          placeholder="Search dependencies by name..." 
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          style={{ width: '100%', padding: '10px 12px 10px 40px', borderRadius: '8px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', color: 'white' }}
                        />
                      </div>
                      
                      <label htmlFor="ecosystem-select" style={{ display: 'none' }}>Ecosystem Filter</label>
                      <select 
                        id="ecosystem-select"
                        value={selectedEcosystem} 
                        onChange={(e) => setSelectedEcosystem(e.target.value)}
                        style={{ padding: '10px', borderRadius: '8px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', color: 'white' }}
                      >
                        <option value="all">All Ecosystems</option>
                        <option value="npm">NPM (JavaScript)</option>
                        <option value="pypi">PyPI (Python)</option>
                        <option value="maven">Maven (Java)</option>
                      </select>

                      <label htmlFor="risk-select" style={{ display: 'none' }}>Risk Filter</label>
                      <select 
                        id="risk-select"
                        value={selectedRisk} 
                        onChange={(e) => setSelectedRisk(e.target.value)}
                        style={{ padding: '10px', borderRadius: '8px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', color: 'white' }}
                      >
                        <option value="all">All Risk Ratings</option>
                        <option value="CRITICAL">Critical Risk</option>
                        <option value="HIGH">High Risk</option>
                        <option value="LOW">Low Risk</option>
                      </select>
                    </div>

                    <table className="glass-panel" style={{ width: '100%', borderCollapse: 'collapse', overflow: 'hidden', textAlign: 'left' }}>
                      <thead>
                        <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-color)' }}>
                          <th style={{ padding: '16px' }}>Component Name</th>
                          <th style={{ padding: '16px' }}>Version</th>
                          <th style={{ padding: '16px' }}>Ecosystem</th>
                          <th style={{ padding: '16px' }}>License</th>
                          <th style={{ padding: '16px' }}>Risk Rating</th>
                          <th style={{ padding: '16px' }}>AI Anomaly Score</th>
                          <th style={{ padding: '16px' }}>Depth</th>
                          <th style={{ padding: '16px' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedProject?.components
                          .filter(c => c.name.toLowerCase().includes(searchQuery.toLowerCase()))
                          .filter(c => selectedEcosystem === 'all' || c.ecosystem === selectedEcosystem)
                          .filter(c => selectedRisk === 'all' || c.risk_level === selectedRisk)
                          .map(c => (
                            <React.Fragment key={c.id}>
                              <tr style={{ borderBottom: '1px solid var(--border-color)', cursor: 'pointer' }} onClick={() => setExpandedCompId(expandedCompId === c.purl ? null : c.purl)}>
                                <td style={{ padding: '16px', fontWeight: 600 }}>{c.name}</td>
                                <td style={{ padding: '16px' }} className="mono-text">{c.version}</td>
                                <td style={{ padding: '16px' }}>
                                  <span style={{ fontSize: '0.8rem', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: '4px' }}>{c.ecosystem}</span>
                                </td>
                                <td style={{ padding: '16px' }}>{c.license}</td>
                                <td style={{ padding: '16px' }}>
                                  <span className={`badge ${getRiskBadgeClass(c.risk_level)}`}>{c.risk_level} ({c.risk_score})</span>
                                </td>
                                <td style={{ padding: '16px' }}>
                                  <span style={{ color: c.anomaly_score > 60 ? 'var(--critical)' : 'inherit', fontWeight: 700 }}>{c.anomaly_score}/100</span>
                                </td>
                                <td style={{ padding: '16px' }}>{c.direct ? 'Direct (0)' : `Transitive (${c.depth})`}</td>
                                <td style={{ padding: '16px' }}>
                                  <button type="button" className="btn-secondary" style={{ padding: '4px 8px', fontSize: '0.75rem' }}>
                                    {expandedCompId === c.purl ? 'Collapse' : 'Explain Findings'}
                                  </button>
                                </td>
                              </tr>

                              {/* Expanded Row Explanations */}
                              {expandedCompId === c.purl && (
                                <tr style={{ background: 'rgba(99, 102, 241, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                                  <td colSpan={8} style={{ padding: '24px' }}>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                                      
                                      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px' }}>
                                        <div>
                                          <h4 style={{ fontSize: '0.95rem', marginBottom: '8px', color: 'var(--primary)' }}>Contextual Security Assessment</h4>
                                          <p style={{ fontSize: '0.85rem' }}>{c.explanation}</p>
                                          
                                          {c.vulnerabilities.length > 0 && (
                                            <div style={{ marginTop: '16px' }}>
                                              <h5 style={{ fontSize: '0.85rem', color: 'var(--critical)', marginBottom: '8px' }}>Matched Vulnerabilities ({c.vulnerabilities.length})</h5>
                                              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                                {c.vulnerabilities.map(v => (
                                                  <div key={v.cve_id} style={{ background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
                                                    <span style={{ fontWeight: 700, fontSize: '0.8rem', color: 'var(--critical)' }}>{v.cve_id} (CVSS: {v.cvss_score})</span>
                                                    <p style={{ fontSize: '0.8rem', marginTop: '4px', color: 'var(--text-secondary)' }}>{v.description}</p>
                                                  </div>
                                                ))}
                                              </div>
                                            </div>
                                          )}
                                        </div>

                                        <div style={{ background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.8rem' }}>
                                          <div>
                                            <span style={{ color: 'var(--text-muted)' }}>Package PURL: </span>
                                            <span className="mono-text" style={{ wordBreak: 'break-all', display: 'block', marginTop: '2px' }}>{c.purl}</span>
                                          </div>
                                          <div>
                                            <span style={{ color: 'var(--text-muted)' }}>Evidence Confidence Score: </span>
                                            <span style={{ fontWeight: 700, color: 'var(--low)' }}>{Math.round(c.confidence * 100)}% ({c.source_file})</span>
                                          </div>
                                          <div>
                                            <span style={{ color: 'var(--text-muted)' }}>License Compliance: </span>
                                            <span style={{ fontWeight: 700 }}>{c.license} (Class: Approved)</span>
                                          </div>
                                        </div>
                                      </div>

                                      {/* VEX Formulation Engine */}
                                      <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                                        <h4 style={{ fontSize: '0.95rem', marginBottom: '12px', color: 'var(--info)' }}>VEX (Vulnerability Exploitability eXchange) Formulator</h4>
                                        <form onSubmit={handleUpdateVex} style={{ display: 'flex', gap: '12px', flexDirection: 'column' }}>
                                          <div style={{ display: 'flex', gap: '12px' }}>
                                            <label htmlFor="vex-status-select" style={{ display: 'none' }}>VEX Status</label>
                                            <select 
                                              id="vex-status-select"
                                              value={vexStatus} 
                                              onChange={(e) => setVexStatus(e.target.value)}
                                              style={{ padding: '8px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                                            >
                                              <option value="AFFECTED">AFFECTED</option>
                                              <option value="NOT_AFFECTED">NOT AFFECTED (Vulnerability unreachable)</option>
                                              <option value="UNDER_INVESTIGATION">UNDER INVESTIGATION</option>
                                              <option value="FIXED">FIXED (Virtual patch applied)</option>
                                            </select>
                                            <label htmlFor="vex-justification-input" style={{ display: 'none' }}>VEX Justification</label>
                                            <input 
                                              id="vex-justification-input"
                                              type="text" 
                                              placeholder="Provide exploitability justification (e.g. library functions not invoked by compiler entrypoints)..." 
                                              value={vexJustification}
                                              onChange={(e) => setVexJustification(e.target.value)}
                                              style={{ flex: 1, padding: '8px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                                            />
                                            <button type="submit" className="btn-primary" style={{ padding: '8px 16px' }}>
                                              Update VEX Statement
                                            </button>
                                          </div>
                                          {vexFeedback && (
                                            <span style={{ fontSize: '0.8rem', color: 'var(--low)' }}>{vexFeedback}</span>
                                          )}
                                        </form>
                                      </div>

                                    </div>
                                  </td>
                                </tr>
                              )}
                            </React.Fragment>
                          ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* SUBTAB 2: DEPENDENCY ATTACK GRAPH */}
                {detailSubtab === 'graph' && (
                  <div className="animate-fade-in glass-panel" style={{ padding: '24px', display: 'grid', gridTemplateColumns: '2fr 1.2fr', gap: '24px' }}>
                    
                    {/* SVG Graphic Canvas */}
                    <div style={{ border: '1px solid var(--border-color)', borderRadius: '12px', background: '#05070c', height: '400px', position: 'relative', overflow: 'hidden' }}>
                      <span style={{ position: 'absolute', top: '12px', left: '12px', fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>Interactive Dependency Node Graph</span>
                      
                      <svg style={{ width: '100%', height: '100%' }}>
                        {/* Define arrows */}
                        <defs>
                          <marker id="arrow" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.15)" />
                          </marker>
                        </defs>

                        {/* Hardcoded SVG nodes representing MOCK_COMPONENTS_1 relations */}
                        {/* Edges */}
                        <line x1="60" y1="200" x2="200" y2="100" stroke="rgba(255,255,255,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
                        <line x1="60" y1="200" x2="200" y2="200" stroke="rgba(255,255,255,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
                        <line x1="60" y1="200" x2="200" y2="300" stroke="rgba(255,255,255,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
                        <line x1="200" y1="100" x2="340" y2="100" stroke="rgba(255,255,255,0.1)" strokeWidth="2" markerEnd="url(#arrow)" />
                        
                        {/* Node: Application Root */}
                        <circle cx="60" cy="200" r="22" fill="#6366f1" style={{ cursor: 'pointer' }} onClick={() => {
                          setSelectedGraphNode({ name: "Application Root", version: "1.0.0", risk_score: 0, purl: "root", description: "Your target scanned project repository workspace." });
                          setGraphBlastRadius(null);
                        }} />
                        <text x="60" y="235" fill="white" fontSize="10" textAnchor="middle" fontWeight="bold">Application</text>
                        
                        {/* Node: lodash */}
                        <circle cx="200" cy="100" r="18" fill="var(--high)" style={{ cursor: 'pointer' }} onClick={() => {
                          setSelectedGraphNode({ name: "lodash", version: "4.17.11", risk_score: 75, purl: "pkg:npm/lodash@4.17.11", description: "Prototype pollution vulnerability present (CVE-2019-10744)." });
                          setGraphBlastRadius({ path: "Application -> lodash -> follow-redirects", count: 1 });
                        }} />
                        <text x="200" y="132" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">lodash</text>

                        {/* Node: log4j */}
                        <circle cx="200" cy="200" r="18" fill="var(--critical)" style={{ cursor: 'pointer' }} onClick={() => {
                          setSelectedGraphNode({ name: "log4j-core", version: "2.14.0", risk_score: 95, purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", description: "Critical JNDI RCE vulnerability present (CVE-2021-44228)." });
                          setGraphBlastRadius({ path: "Application -> log4j-core", count: 0 });
                        }} />
                        <text x="200" y="232" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">log4j-core</text>

                        {/* Node: express */}
                        <circle cx="200" cy="300" r="18" fill="var(--low)" style={{ cursor: 'pointer' }} onClick={() => {
                          setSelectedGraphNode({ name: "express", version: "4.17.1", risk_score: 10, purl: "pkg:npm/express@4.17.1", description: "Secure, no vulnerabilities detected." });
                          setGraphBlastRadius(null);
                        }} />
                        <text x="200" y="332" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">express</text>

                        {/* Node: follow-redirects */}
                        <circle cx="340" cy="100" r="18" fill="var(--high)" style={{ cursor: 'pointer' }} onClick={() => {
                          setSelectedGraphNode({ name: "follow-redirects", version: "1.15.2", risk_score: 65, purl: "pkg:npm/follow-redirects@1.15.2", description: "Transitive dependency of lodash containing redirect leak." });
                          setGraphBlastRadius({ path: "Application -> lodash -> follow-redirects", count: 1 });
                        }} />
                        <text x="340" y="132" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">follow-redirects</text>
                      </svg>
                    </div>

                    {/* Blast Radius details */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      <h4 style={{ fontSize: '1.1rem', color: 'var(--primary)' }}>Threat Path Intelligence</h4>
                      
                      {selectedGraphNode ? (
                        <div style={{ background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Node Name:</span>
                            <h5 style={{ fontSize: '1rem', fontWeight: 700 }}>{selectedGraphNode.name}</h5>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Package PURL:</span>
                            <span className="mono-text" style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>{selectedGraphNode.purl}</span>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Severity / Risk:</span>
                            <span style={{ fontWeight: 700, display: 'block', color: selectedGraphNode.risk_score > 60 ? 'var(--critical)' : 'var(--low)' }}>{selectedGraphNode.risk_score}/100</span>
                          </div>
                          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{selectedGraphNode.description}</p>
                          
                          {graphBlastRadius && (
                            <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '12px', marginTop: '8px' }}>
                              <span style={{ fontSize: '0.8rem', color: 'var(--high)', fontWeight: 700, display: 'block', marginBottom: '4px' }}>Blast Radius: {graphBlastRadius.count} Downstream dependents affected</span>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)', background: 'rgba(0,0,0,0.3)', padding: '6px', borderRadius: '4px' }}>
                                <GitBranch size={12} /> <span className="mono-text">{graphBlastRadius.path}</span>
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          <HelpCircle size={32} style={{ margin: '0 auto 12px auto', opacity: 0.5 }} />
                          <p>Click any node inside the canvas to trace its threat propagation path and calculate blast radius metrics.</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* SUBTAB 3: COMPLIANCE & POLICIES */}
                {detailSubtab === 'compliance' && (
                  <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                    <div className="glass-panel" style={{ padding: '24px', borderLeft: '4px solid var(--critical)' }}>
                      <h4 style={{ fontSize: '1.1rem', color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                        <XCircle /> CI/CD Build Gate Decision: BLOCKED
                      </h4>
                      <p style={{ fontSize: '0.85rem' }}>The security compliance gate failed because components violated active policy rules. Critical CVEs and malicious code features were detected.</p>
                    </div>

                    <section className="glass-panel" style={{ padding: '24px' }}>
                      <h4 style={{ fontSize: '1rem', marginBottom: '16px' }}>Developer Compliance Diagnostic Output</h4>
                      <pre style={{ background: '#05070c', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)', color: '#ef4444', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
{`====================================================
 SBOMGUARD CI/CD GATE SECURITY ANALYSIS REPORT
 STATUS: BLOCK (Exit Code: 2)
====================================================

[!] Flagged 3 package violations:
  1. [BLOCK] org.apache.logging.log4j:log4j-core@2.14.0 (maven)
     - Vulnerability CVSS score 10.0 triggers BLOCK rule (>= 9.0)
  2. [BLOCK] sih-malicious-package@1.0.0 (npm)
     - AI Anomaly score 85 triggers REVIEW/BLOCK rule (>= 80)
  3. [REVIEW] lodash@4.17.11 (npm)
     - Vulnerability CVSS score 7.4 triggers REVIEW threshold (>= 7.0)

Remediation Recommendations:
  - org.apache.logging.log4j:log4j-core: Upgrade log4j-core to version 2.15.0 or higher.
  - lodash: Upgrade lodash to version 4.17.21.

====================================================`}
                      </pre>
                    </section>
                  </div>
                )}

                {/* SUBTAB 4: HISTORY & DIFF */}
                {detailSubtab === 'diff' && (
                  <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                    
                    {/* Selectors */}
                    <div className="glass-panel" style={{ padding: '24px', display: 'flex', gap: '16px', alignItems: 'flex-end' }}>
                      <div style={{ flex: 1 }}>
                        <label htmlFor="base-version-select" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: 600 }}>Select Base Scan Version</label>
                        <select 
                          id="base-version-select"
                          value={selectedVersionBase}
                          onChange={(e) => setSelectedVersionBase(e.target.value)}
                          style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                        >
                          <option value="">-- Choose Base --</option>
                          {versionHistory.map(v => (
                            <option key={v.sbom_id} value={v.sbom_id}>Version {v.version_number} ({v.components_count} packages) - {new Date(v.created_at).toLocaleDateString()}</option>
                          ))}
                        </select>
                      </div>

                      <div style={{ flex: 1 }}>
                        <label htmlFor="head-version-select" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: 600 }}>Select Head Scan Version</label>
                        <select 
                          id="head-version-select"
                          value={selectedVersionHead}
                          onChange={(e) => setSelectedVersionHead(e.target.value)}
                          style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                        >
                          <option value="">-- Choose Head --</option>
                          {versionHistory.map(v => (
                            <option key={v.sbom_id} value={v.sbom_id}>Version {v.version_number} ({v.components_count} packages) - {new Date(v.created_at).toLocaleDateString()}</option>
                          ))}
                        </select>
                      </div>

                      <button type="button" className="btn-primary" onClick={handleCompareVersions} style={{ padding: '10px 24px' }}>
                        Compute Diff Tree
                      </button>
                    </div>

                    {/* Diff Output */}
                    {diffResult && (
                      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h4 style={{ fontSize: '1rem', color: 'var(--primary)' }}>SBOM Diff Logs</h4>
                        
                        {diffResult.added.length === 0 && diffResult.removed.length === 0 && diffResult.updated.length === 0 ? (
                          <span style={{ fontSize: '0.85rem' }}>No package shifts detected between these scan sessions.</span>
                        ) : (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.85rem' }}>
                            {diffResult.added.map((a) => (
                              <div key={`${a.name}-${a.version}-${a.ecosystem}`} style={{ padding: '8px', borderRadius: '6px', background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)', color: 'var(--low)' }}>
                                <strong>+ ADDED Component:</strong> {a.name}@{a.version} ({a.ecosystem})
                              </div>
                            ))}
                            
                            {diffResult.updated.map((u) => (
                              <div key={`${u.name}-${u.old_version}-${u.new_version}`} style={{ padding: '8px', borderRadius: '6px', background: 'rgba(59, 130, 246, 0.05)', border: '1px solid rgba(59, 130, 246, 0.2)', color: 'var(--info)' }}>
                                <strong>&Delta; MODIFIED Version:</strong> {u.name} upgraded from {u.old_version} to {u.new_version}
                              </div>
                            ))}
                            
                            {diffResult.removed.map((r) => (
                              <div key={`${r.name}-${r.version}`} style={{ padding: '8px', borderRadius: '6px', background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.2)', color: 'var(--critical)' }}>
                                <strong>- REMOVED Component:</strong> {r.name}@{r.version}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* SUBTAB 5: WHAT-IF RISK SIMULATOR */}
                {detailSubtab === 'whatif' && (
                  <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                    <div className="glass-panel" style={{ padding: '24px' }}>
                      <h4 style={{ fontSize: '1rem', marginBottom: '16px' }}>Run Simulation (Assess hypothetical patch risk changes)</h4>
                      <form onSubmit={handleWhatIfSimulation} style={{ display: 'flex', gap: '16px', alignItems: 'flex-end' }}>
                        <div style={{ flex: 1.5 }}>
                          <label htmlFor="whatif-purl-select" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Target Component (PURL)</label>
                          <select 
                            id="whatif-purl-select"
                            value={whatIfPurl} 
                            onChange={(e) => setWhatIfPurl(e.target.value)}
                            style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                          >
                            <option value="">-- Choose package to upgrade --</option>
                            {selectedProject?.components
                              .filter(c => c.vulnerabilities.length > 0)
                              .map(c => (
                                <option key={c.purl} value={c.purl}>{c.name} (Current: {c.version})</option>
                              ))}
                          </select>
                        </div>

                        <div style={{ flex: 1 }}>
                          <label htmlFor="whatif-version-input" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Simulation Upgrade Version</label>
                          <input 
                            id="whatif-version-input"
                            type="text" 
                            placeholder="e.g. 2.15.0" 
                            value={whatIfVersion}
                            onChange={(e) => setWhatIfVersion(e.target.value)}
                            style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                          />
                        </div>

                        <button type="submit" className="btn-primary" style={{ padding: '10px 24px' }}>
                          Run Sandbox Simulation
                        </button>
                      </form>
                    </div>

                    {whatIfResult && (
                      <div className="glass-panel" style={{ padding: '24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                        <div>
                          <h4 style={{ fontSize: '1.1rem', color: 'var(--primary)', marginBottom: '16px' }}>Projected Risk Shift</h4>
                          
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                              <span>Current Max Risk:</span>
                              <span style={{ fontWeight: 700, color: 'var(--critical)' }}>95/100</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                              <span>Projected Max Risk:</span>
                              <span style={{ fontWeight: 700, color: whatIfResult.projected_total_risk > 70 ? 'var(--high)' : 'var(--low)' }}>{whatIfResult.projected_total_risk}/100</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                              <span>Risk Delta:</span>
                              <span style={{ fontWeight: 700, color: 'var(--low)' }}>-{95 - whatIfResult.projected_total_risk} Risk points</span>
                            </div>
                          </div>
                        </div>

                        <div>
                          <h4 style={{ fontSize: '1.1rem', color: 'var(--info)', marginBottom: '16px' }}>Projected Vulnerability Reductions</h4>
                          
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                              <span>Critical Disclosures:</span>
                              <span>1 &rarr; <span style={{ fontWeight: 700, color: 'var(--low)' }}>{whatIfResult.projected_critical_count}</span></span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                              <span>Remaining Vuln count:</span>
                              <span>5 &rarr; <span style={{ fontWeight: 700 }}>{whatIfResult.projected_vulnerability_count}</span></span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* SUBTAB 6: EXECUTIVE REPORTS */}
                {detailSubtab === 'reports' && (
                  <div className="animate-fade-in glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <h4 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>Compliance Document Generator</h4>
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>Download standardized CycloneDX & SPDX software bill of material files or export CSV security reports.</p>
                    
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
                      <button 
                        type="button" 
                        className="btn-secondary" 
                        onClick={() => handleDownloadReport(`/api/reports/project/${selectedProjectId}/cyclonedx`, `cyclonedx_${selectedProject?.name || 'report'}.json`)} 
                        style={{ width: '100%', justifyContent: 'center', padding: '16px' }}
                      >
                        <Download size={20} color="var(--primary)" /> Download CycloneDX (JSON)
                      </button>
                      
                      <button 
                        type="button" 
                        className="btn-secondary" 
                        onClick={() => handleDownloadReport(`/api/reports/project/${selectedProjectId}/spdx`, `spdx_${selectedProject?.name || 'report'}.json`)} 
                        style={{ width: '100%', justifyContent: 'center', padding: '16px' }}
                      >
                        <Download size={20} color="var(--info)" /> Download SPDX (JSON)
                      </button>

                      <button 
                        type="button" 
                        className="btn-secondary" 
                        onClick={() => handleDownloadReport(`/api/reports/project/${selectedProjectId}/csv`, `sbom_report_${selectedProject?.name || 'report'}.csv`)} 
                        style={{ width: '100%', justifyContent: 'center', padding: '16px' }}
                      >
                        <Download size={20} color="var(--low)" /> Download CSV Audit Report
                      </button>
                    </div>
                  </div>
                )}

              </div>
            )}

          </div>
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92
        )}

        {activeTab === 'tickets' && (
<<<<<<< HEAD
          <TicketsPage 
            tickets={tickets} 
            isLoading={isLoading} 
            onUpdateTicketStatus={handleUpdateTicketStatus}
          />
=======
          <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <h3 style={{ fontSize: '1.4rem' }}>Security Remediation Center</h3>
            
            <div className="glass-panel" style={{ padding: '24px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', overflow: 'hidden', textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border-color)' }}>
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
                  {tickets.map(t => (
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
                          ...getTicketStatusBadgeStyle(t.status)
                        }}>{t.status}</span>
                      </td>
                      <td style={{ padding: '16px' }}>
                        {t.status !== 'RESOLVED' ? (
                          <button type="button" className="btn-secondary" onClick={() => handleUpdateTicketStatus(t.ticket_id, t.status)} style={{ padding: '6px 12px', fontSize: '0.75rem' }}>
                            {t.status === 'OPEN' ? 'Start Work' : 'Resolve Ticket'}
                          </button>
                        ) : (
                          <span style={{ color: 'var(--low)', display: 'flex', alignItems: 'center', gap: '4px' }}><Check size={16} /> Closed</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92
        )}

        {activeTab === 'policies' && (
<<<<<<< HEAD
          <PoliciesPage 
            policies={policies}
            onTogglePolicy={handleTogglePolicy}
            onCreatePolicy={handleCreatePolicy}
          />
=======
          <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <h3 style={{ fontSize: '1.4rem' }}>Compliance Policy Studio (Policy-as-Code)</h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '24px' }}>
              
              {/* Active Rules list */}
              <section className="glass-panel" style={{ padding: '24px' }}>
                <h4 style={{ fontSize: '1.1rem', marginBottom: '16px' }}>Active Compliance Rules</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {policies.map(p => (
                    <div key={p.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', borderRadius: '8px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-color)' }}>
                      <div>
                        <h5 style={{ fontWeight: 700 }}>{p.name}</h5>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Rule: {p.rule_type} {p.rule_condition} &rarr; Action: <strong>{p.action}</strong></span>
                      </div>

                      <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                        <button 
                          type="button"
                          className="btn-secondary" 
                          onClick={() => handleTogglePolicy(p.id, p.is_active)}
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
                <form onSubmit={handleCreatePolicy} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <label htmlFor="new-policy-name" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Rule Name</label>
                    <input 
                      id="new-policy-name"
                      type="text" 
                      placeholder="e.g. Block high anomaly packages" 
                      value={newPolicyName}
                      onChange={(e) => setNewPolicyName(e.target.value)}
                      style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                    />
                  </div>

                  <div>
                    <label htmlFor="new-policy-type" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Rule Trigger Type</label>
                    <select 
                      id="new-policy-type"
                      value={newPolicyType} 
                      onChange={(e) => setNewPolicyType(e.target.value)}
                      style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                    >
                      <option value="CVSS_THRESHOLD">CVSS Vulnerability Threshold</option>
                      <option value="AI_ANOMALY">AI Anomaly Score</option>
                      <option value="FORBIDDEN_LICENSE">Forbidden License Flag</option>
                    </select>
                  </div>

                  <div>
                    <label htmlFor="new-policy-cond" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Condition Pattern</label>
                    <input 
                      id="new-policy-cond"
                      type="text" 
                      placeholder="e.g. >= 9.0 or FORBIDDEN" 
                      value={newPolicyCond}
                      onChange={(e) => setNewPolicyCond(e.target.value)}
                      style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
                    />
                  </div>

                  <div>
                    <label htmlFor="new-policy-action" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Compliance Action</label>
                    <select 
                      id="new-policy-action"
                      value={newPolicyAction} 
                      onChange={(e) => setNewPolicyAction(e.target.value)}
                      style={{ width: '100%', padding: '10px', borderRadius: '6px', background: '#0b0f19', border: '1px solid var(--border-color)', color: 'white' }}
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
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92
        )}

        {activeTab === 'audit' && (
<<<<<<< HEAD
          <AuditPage 
            auditLogs={auditLogs}
            isLoading={isLoading}
=======
          <AuditLogsTab
            auditLogs={auditLogs}
>>>>>>> aa70ce9d899ddd65ff93be17b470b72d189abe92
          />
        )}
      </main>
    </div>
  );
}
