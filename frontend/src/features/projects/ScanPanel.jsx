import React, { useState, useRef } from 'react';
import { Activity, Upload, CheckCircle, Circle, Loader2, GitBranch, RefreshCw, FileArchive } from 'lucide-react';
import { useLocalStorage } from '../../hooks/useLocalStorage';

const PIPELINE_STAGES = [
  { id: 'INITIALIZING', label: 'Initialization' },
  { id: 'DISCOVERY', label: 'Repository Discovery' },
  { id: 'VERSION_RESOLUTION', label: 'Version Resolution' },
  { id: 'GRAPH_ANALYSIS', label: 'Graph Analysis' },
  { id: 'RISK_ANALYSIS', label: 'Risk Analysis' },
  { id: 'POLICY_EVALUATION', label: 'Policy Evaluation' },
  { id: 'SBOM_GENERATION', label: 'SBOM Generation' },
  { id: 'FINALIZING', label: 'Finalizing' },
];

export default function ScanPanel({ project, scanProgress, scanMessage, scanLogs, scanDetails, onTriggerScan, onGithubRescan, onZipRescan }) {
  const [localScanPath, setLocalScanPath] = useLocalStorage('scan_path', '');
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  const handleLocalSubmit = (e) => {
    e.preventDefault();
    if (!localScanPath) {
      alert("Please enter a scan directory path.");
      return;
    }
    onTriggerScan(localScanPath);
  };

  const handleZipRescan = () => {
    if (!selectedFile) {
      alert("Please select a ZIP file first.");
      return;
    }
    onZipRescan(selectedFile);
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const scanSource = project?.latest_scan_source;

  return (
    <section className="glass-panel" style={{ padding: '24px' }}>
      <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Activity size={18} /> Trigger Compliance Audit Scanning
      </h3>
      
      {/* === GitHub Source === */}
      {scanSource === 'github' ? (
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div style={{ flex: 1, padding: '14px 16px', background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <GitBranch size={18} color="var(--primary)" />
            <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Linked to <strong style={{ color: 'var(--text-primary)' }}>{project.latest_scan_github_url}</strong>
            </span>
          </div>
          <button 
            className="btn-primary" 
            disabled={scanProgress}
            onClick={onGithubRescan}
            style={{ display: 'flex', alignItems: 'center', gap: '8px', whiteSpace: 'nowrap' }}
          >
            <RefreshCw size={16} className={scanProgress ? 'animate-spin' : ''} />
            {scanProgress ? 'Scanning...' : 'Re-scan from GitHub'}
          </button>
        </div>

      /* === ZIP Upload Source === */
      ) : scanSource === 'upload' ? (
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div style={{ flex: 1, padding: '14px 16px', background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileArchive size={18} color="#10b981" />
            <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Imported via <strong style={{ color: 'var(--text-primary)' }}>ZIP Upload</strong>
              {project.latest_scan_status === 'COMPLETED' && <span style={{ marginLeft: '8px', color: '#10b981', fontSize: '0.8rem' }}>✓ Scanned</span>}
              {project.latest_scan_status === 'RUNNING' && <span style={{ marginLeft: '8px', color: 'var(--primary)', fontSize: '0.8rem' }}>⟳ Scanning...</span>}
              {project.latest_scan_status === 'PENDING' && <span style={{ marginLeft: '8px', color: 'var(--medium)', fontSize: '0.8rem' }}>⏳ Pending...</span>}
            </span>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <label style={{ position: 'relative', cursor: 'pointer' }}>
              <input 
                ref={fileInputRef}
                type="file" 
                accept=".zip" 
                onChange={(e) => setSelectedFile(e.target.files[0])}
                style={{ position: 'absolute', inset: 0, opacity: 0, cursor: 'pointer', width: '100%' }}
              />
              <span className="btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '10px 14px', fontSize: '0.85rem', whiteSpace: 'nowrap' }}>
                <FileArchive size={14} /> {selectedFile ? selectedFile.name : 'Choose ZIP'}
              </span>
            </label>
            <button 
              className="btn-primary" 
              disabled={scanProgress || !selectedFile}
              onClick={handleZipRescan}
              style={{ display: 'flex', alignItems: 'center', gap: '8px', whiteSpace: 'nowrap' }}
            >
              <RefreshCw size={16} className={scanProgress ? 'animate-spin' : ''} />
              {scanProgress ? 'Scanning...' : 'Re-scan ZIP'}
            </button>
          </div>
        </div>

      /* === Local/Default Source === */
      ) : (
        <form onSubmit={handleLocalSubmit} style={{ display: 'flex', gap: '16px' }}>
          <input 
            type="text" 
            placeholder="Enter local repository absolute directory path (e.g. C:\Users\User\my-app)..." 
            value={localScanPath}
            onChange={(e) => setLocalScanPath(e.target.value)}
            style={{ flex: 1, padding: '12px', borderRadius: '8px', background: 'rgba(0,0,0,0.05)', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
          />
          <button type="submit" className="btn-primary" disabled={scanProgress}>
            <Upload size={16} /> {scanProgress ? 'Scanning...' : 'Trigger Scan Engine'}
          </button>
        </form>
      )}
      
      {scanMessage && !scanDetails && (
        <div style={{ marginTop: '12px', padding: '8px 12px', borderRadius: '6px', background: 'rgba(0,0,0,0.05)', fontSize: '0.85rem' }}>
          <strong>Status: </strong> {scanMessage}
        </div>
      )}

      {scanDetails && (
        <div style={{ marginTop: '24px', padding: '20px', borderRadius: '8px', background: 'var(--surface-color)', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h4 style={{ margin: 0, fontSize: '0.95rem' }}>Scan Pipeline Progress</h4>
            <span style={{ fontSize: '0.85rem', color: 'var(--primary)', fontWeight: 600 }}>{scanDetails.status === 'COMPLETED' ? 100 : (scanDetails.overall_progress || 0)}%</span>
          </div>
          
          <div style={{ position: 'relative', display: 'flex', justifyContent: 'space-between', marginBottom: '24px' }}>
            {/* Progress Line Background */}
            <div style={{ position: 'absolute', top: '12px', left: '0', right: '0', height: '2px', background: 'rgba(0,0,0,0.1)', zIndex: 0 }} />
            
            {/* Active Progress Line */}
            <div style={{ position: 'absolute', top: '12px', left: '0', width: `${scanDetails.status === 'COMPLETED' ? 100 : (scanDetails.overall_progress || 0)}%`, height: '2px', background: 'var(--primary)', zIndex: 1, transition: 'width 0.5s ease-in-out' }} />

            {PIPELINE_STAGES.map((stage, idx) => {
              const stageIndex = PIPELINE_STAGES.findIndex(s => s.id === scanDetails.current_stage);
              const isCompleted = idx < stageIndex || scanDetails.status === 'COMPLETED';
              const isCurrent = idx === stageIndex && scanDetails.status !== 'COMPLETED' && scanDetails.status !== 'FAILED';
              const isFailed = idx === stageIndex && scanDetails.status === 'FAILED';
              
              let Icon = Circle;
              let color = 'var(--text-muted)';
              if (isCompleted) {
                Icon = CheckCircle;
                color = '#10b981';
              } else if (isCurrent) {
                Icon = Loader2;
                color = 'var(--primary)';
              } else if (isFailed) {
                Icon = Circle;
                color = '#ef4444';
              }
              
              return (
                <div key={stage.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 2, background: 'var(--surface-color)', padding: '0 4px' }}>
                  <div style={{ color, animation: isCurrent ? 'spin 2s linear infinite' : 'none' }}>
                    <Icon size={24} fill={isCompleted ? color : 'transparent'} stroke={isCompleted ? '#000' : 'currentColor'} />
                  </div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-primary)', textAlign: 'center', width: '70px', lineHeight: '1.2' }}>
                    {stage.label}
                  </span>
                </div>
              );
            })}
          </div>

          <div style={{ padding: '12px', background: 'rgba(0,0,0,0.05)', borderRadius: '6px', borderLeft: `3px solid ${scanDetails.status === 'FAILED' ? '#ef4444' : 'var(--primary)'}` }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 500, marginBottom: '4px' }}>Current Operation:</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{scanDetails.stage_message || scanMessage}</div>
          </div>
        </div>
      )}

      {scanLogs && (
        <div style={{ marginTop: '16px', background: '#ffffff', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: 600 }}>Diagnostic Scan Logs:</span>
          <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#10b981', maxHeight: '180px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
            {scanLogs}
          </pre>
        </div>
      )}
    </section>
  );
}
