import React, { useEffect } from 'react';
import { useLocalStorage } from './hooks/useLocalStorage';
import { usePlatformData } from './hooks/usePlatformData';

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

  const handleCreateProject = (name) => {
    setProjects(prev => [
      ...prev,
      { id: Date.now(), name, description: "Custom developer codebase container.", created_at: new Date().toISOString(), latest_scan_status: "NEVER_SCANNED", vulnerability_count: 0, risk_score: 0, risk_level: "LOW", quality_score: 100 }
    ]);
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
