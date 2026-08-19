import { useState, useCallback } from 'react';
import { API_BASE, MOCK_PROJECTS, MOCK_COMPONENTS, MOCK_VERSION_HISTORY } from '../constants/mock';

/**
 * useProjectDetails — manages per-project data and the scan pipeline.
 * Keeps scan state (progress, logs, message) fully isolated from other pages.
 */
export function useProjectDetails(isOfflineMode) {
  const [isLoading, setIsLoading] = useState(false);
  const [selectedProject, setSelectedProject] = useState(null);
  const [versionHistory, setVersionHistory] = useState([]);

  // Scan pipeline state
  const [scanProgress, setScanProgress] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [scanLogs, setScanLogs] = useState('');
  const [scanDetails, setScanDetails] = useState(null);

  const fetchProjectDetails = useCallback(async (projId) => {
    if (!projId) return;
    setIsLoading(true);
    setSelectedProject(null);

    if (isOfflineMode) {
      const match = MOCK_PROJECTS.find(p => p.id === projId);
      if (match) {
        setSelectedProject({
          ...match,
          risk_summary: { level: match.risk_level, score: match.risk_score },
          components: MOCK_COMPONENTS,
          vulnerabilities: MOCK_COMPONENTS.flatMap(c => c.vulnerabilities),
          anomalies: MOCK_COMPONENTS.filter(c => c.anomaly_score > 40).map(c => ({
            purl: c.purl,
            score: c.anomaly_score,
            probability: c.anomaly_score / 100,
            classification: c.anomaly_score > 60 ? 'SUSPICIOUS' : 'NORMAL',
            indicators: c.name.includes('malicious')
              ? ['obfuscation', 'install scripts', 'network socket calls']
              : ['minor anomalies'],
          })),
          remediations: MOCK_COMPONENTS.filter(c => c.vulnerabilities.length > 0).map(c => ({
            purl: c.purl,
            current_version: c.version,
            recommended_version: c.version.startsWith('4') ? '4.17.21' : '2.15.0',
            upgrade_impact: 'Minor logic modifications. Review downstream API changes.',
          })),
        });
        setVersionHistory(MOCK_VERSION_HISTORY);
      }
    } else {
      try {
        const [detailRes, historyRes] = await Promise.allSettled([
          fetch(`${API_BASE}/api/projects/${projId}`),
          fetch(`${API_BASE}/api/projects/${projId}/history`),
        ]);
        if (detailRes.status === 'fulfilled' && detailRes.value.ok)
          setSelectedProject(await detailRes.value.json());
        if (historyRes.status === 'fulfilled' && historyRes.value.ok)
          setVersionHistory(await historyRes.value.json());
      } catch (e) {
        console.error('[SBOMGuard] Failed to load project details', e);
      }
    }
    setIsLoading(false);
  }, [isOfflineMode]);

  const triggerScan = useCallback(async (projId, scanPath, onComplete) => {
    if (!scanPath) return;
    setScanProgress(true);
    setScanMessage('Contacting scanner agent...');
    setScanLogs('Initiating scan...\n');
    setScanDetails({ current_stage: 'INITIALIZING', overall_progress: 0, stage_status: 'RUNNING' });

    if (isOfflineMode) {
      const steps = [
        [500,  '[2026-08-17T09:20:00Z] Scanning local directories for manifest files...\n'],
        [1200, '[2026-08-17T09:20:01Z] Found NPM package.json and Maven pom.xml. Compiling dependencies...\n'],
        [2000, '[2026-08-17T09:20:02Z] Running AI anomaly classification (Isolation Forest and Random Forest)...\n'],
        [2800, '[2026-08-17T09:20:03Z] Correlating vulnerabilities. Flagged 5 CVE findings.\n'],
        [3500, '[2026-08-17T09:20:04Z] SBOM Signing generated. Policy check completed: BLOCKED (Exit Code 2).\n'],
      ];
      steps.forEach(([delay, msg]) => setTimeout(() => setScanLogs(p => p + msg), delay));
      setTimeout(() => {
        setScanProgress(false);
        setScanMessage('Scan Completed. Corporate compliance rules trigger BLOCK: 1 Critical RCE found.');
        setScanDetails({ current_stage: 'FINALIZING', overall_progress: 100, stage_status: 'COMPLETED' });
        fetchProjectDetails(projId);
        onComplete?.();
      }, 3500);
    } else {
      try {
        const r = await fetch(`${API_BASE}/api/scans/local`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ project_id: projId, directory_path: scanPath }),
        });
        if (!r.ok) {
          setScanProgress(false);
          setScanMessage(`Error: ${await r.text()}`);
          return;
        }
        const { scan_id } = await r.json();
        setScanMessage(`Scan initiated (ID: ${scan_id}). Polling status...`);

        const interval = setInterval(async () => {
          try {
            const [statusRes, logsRes] = await Promise.all([
              fetch(`${API_BASE}/api/scans/${scan_id}/status`),
              fetch(`${API_BASE}/api/scans/${scan_id}/logs`),
            ]);
            if (statusRes.ok) {
              const data = await statusRes.json();
              const { status } = data;
              setScanDetails(data);
              if (logsRes.ok) setScanLogs((await logsRes.json()).logs);
              if (status === 'COMPLETED') {
                clearInterval(interval);
                setScanProgress(false);
                setScanMessage('Scan completed successfully.');
                fetchProjectDetails(projId);
                onComplete?.();
              } else if (status === 'FAILED') {
                clearInterval(interval);
                setScanProgress(false);
                setScanMessage('Scan failed. Review diagnostic logs.');
              }
            }
          } catch {
            clearInterval(interval);
            setScanProgress(false);
            setScanMessage('Lost connection during scan polling.');
          }
        }, 1500);
      } catch (e) {
        setScanProgress(false);
        setScanMessage(`Network error: ${e.message}`);
      }
    }
  }, [isOfflineMode, fetchProjectDetails]);

  return {
    isLoading,
    selectedProject, setSelectedProject,
    versionHistory,
    scanProgress, scanMessage, scanLogs, scanDetails,
    setScanMessage, setScanLogs,
    fetchProjectDetails,
    triggerScan,
  };
}
