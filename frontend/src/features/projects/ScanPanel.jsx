import React from 'react';
import { Activity, Upload, CheckCircle, Circle, Loader2 } from 'lucide-react';
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

export default function ScanPanel({ scanProgress, scanMessage, scanLogs, scanDetails, onTriggerScan }) {
  const [localScanPath, setLocalScanPath] = useLocalStorage('scan_path', '');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!localScanPath) {
      alert("Please enter a scan directory path.");
      return;
    }
    onTriggerScan(localScanPath);
  };

  return (
    <section className="glass-panel" style={{ padding: '24px' }}>
      <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Activity size={18} /> Trigger Compliance Audit Scanning
      </h3>
      
      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '16px' }}>
        <input 
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
      
      {scanMessage && !scanDetails && (
        <div style={{ marginTop: '12px', padding: '8px 12px', borderRadius: '6px', background: 'rgba(255,255,255,0.05)', fontSize: '0.85rem' }}>
          <strong>Status: </strong> {scanMessage}
        </div>
      )}

      {scanDetails && (
        <div style={{ marginTop: '24px', padding: '20px', borderRadius: '8px', background: 'var(--surface-color)', border: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h4 style={{ margin: 0, fontSize: '0.95rem' }}>Scan Pipeline Progress</h4>
            <span style={{ fontSize: '0.85rem', color: 'var(--primary)', fontWeight: 600 }}>{scanDetails.overall_progress || 0}%</span>
          </div>
          
          <div style={{ position: 'relative', display: 'flex', justifyContent: 'space-between', marginBottom: '24px' }}>
            {/* Progress Line Background */}
            <div style={{ position: 'absolute', top: '12px', left: '0', right: '0', height: '2px', background: 'rgba(255,255,255,0.1)', zIndex: 0 }} />
            
            {/* Active Progress Line */}
            <div style={{ position: 'absolute', top: '12px', left: '0', width: `${scanDetails.overall_progress || 0}%`, height: '2px', background: 'var(--primary)', zIndex: 1, transition: 'width 0.5s ease-in-out' }} />

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
                  <span style={{ fontSize: '0.7rem', color: isCurrent || isCompleted ? 'white' : 'var(--text-muted)', textAlign: 'center', width: '70px', lineHeight: '1.2' }}>
                    {stage.label}
                  </span>
                </div>
              );
            })}
          </div>

          <div style={{ padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', borderLeft: `3px solid ${scanDetails.status === 'FAILED' ? '#ef4444' : 'var(--primary)'}` }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 500, marginBottom: '4px' }}>Current Operation:</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{scanDetails.stage_message || scanMessage}</div>
          </div>
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
  );
}
