import React, { useEffect } from 'react';
import { useProjectDetails } from '../../hooks/useProjectDetails';
import { useLocalStorage } from '../../hooks/useLocalStorage';
import { PageLoader } from '../../components/Loader';

// Subcomponents
import ScanPanel from './ScanPanel';
import SBOMCatalog from './tabs/SBOMCatalog';
import DependencyGraph from './tabs/DependencyGraph';
import ComplianceGate from './tabs/ComplianceGate';
import VersionDiff from './tabs/VersionDiff';
import WhatIfSimulator from './tabs/WhatIfSimulator';
import Reports from './tabs/Reports';

const TABS = [
  { id: 'sbom', label: 'SBOM Catalog' },
  { id: 'graph', label: 'Dependency Attack Graph' },
  { id: 'compliance', label: 'CI/CD Compliance' },
  { id: 'diff', label: 'History & Diffs' },
  { id: 'whatif', label: 'What-If Risk Simulator' },
  { id: 'reports', label: 'Executive Reports' },
];

export default function ProjectDetail({ projectId, isOfflineMode, onBack, onScanComplete }) {
  const [activeSubTab, setActiveSubTab] = useLocalStorage('detail_subtab', 'sbom');
  
  const {
    isLoading,
    selectedProject,
    versionHistory,
    scanProgress, scanMessage, scanLogs, scanDetails,
    triggerScan,
    fetchProjectDetails,
  } = useProjectDetails(isOfflineMode);

  // Fetch data on mount / when projectId changes
  useEffect(() => {
    fetchProjectDetails(projectId);
  }, [projectId, fetchProjectDetails]);

  if (isLoading || !selectedProject) {
    return <PageLoader label="Loading project asset data..." />;
  }

  const riskBadgeClass = selectedProject.risk_summary?.level === 'CRITICAL' ? 'badge-critical' : 'badge-low';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button className="btn-secondary" onClick={onBack}>
          &larr; Back to Assets
        </button>
        <h2 style={{ fontSize: '1.6rem' }}>{selectedProject.name}</h2>
        <span className={`badge ${riskBadgeClass}`}>
          {selectedProject.risk_summary?.level} Risk ({selectedProject.risk_summary?.score}/100)
        </span>
      </div>

      {/* Trigger Scan Panel */}
      <ScanPanel 
        scanProgress={scanProgress}
        scanMessage={scanMessage}
        scanLogs={scanLogs}
        scanDetails={scanDetails}
        onTriggerScan={(path) => triggerScan(projectId, path, onScanComplete)}
      />

      {/* Subnavigation Tabs */}
      <div style={{ display: 'flex', gap: '12px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
        {TABS.map(tab => (
          <button 
            key={tab.id} 
            className={`btn-secondary ${activeSubTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveSubTab(tab.id)}
            style={{ 
              background: activeSubTab === tab.id ? 'rgba(99,102,241,0.1)' : 'transparent',
              borderColor: activeSubTab === tab.id ? 'var(--primary)' : 'transparent',
              padding: '6px 14px',
              fontSize: '0.85rem'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Subtab Content Routing */}
      {activeSubTab === 'sbom' && (
        <SBOMCatalog 
          project={selectedProject} 
          isOfflineMode={isOfflineMode} 
          onRefresh={() => fetchProjectDetails(projectId)} 
        />
      )}
      {activeSubTab === 'graph' && <DependencyGraph />}
      {activeSubTab === 'compliance' && <ComplianceGate />}
      {activeSubTab === 'diff' && (
        <VersionDiff 
          project={selectedProject} 
          versionHistory={versionHistory} 
          isOfflineMode={isOfflineMode} 
        />
      )}
      {activeSubTab === 'whatif' && (
        <WhatIfSimulator 
          project={selectedProject} 
          isOfflineMode={isOfflineMode} 
        />
      )}
      {activeSubTab === 'reports' && <Reports project={selectedProject} />}
    </div>
  );
}
