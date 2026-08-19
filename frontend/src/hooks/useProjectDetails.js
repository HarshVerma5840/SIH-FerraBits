import { useState, useCallback, useEffect, useRef } from 'react';
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
  
  // Track active polling interval to avoid duplicates
  const pollingRef = useRef(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  // Start polling a scan by ID
  const startPolling = useCallback((scanId, projId, onComplete) => {
    // Clear any existing polling
    if (pollingRef.current) clearInterval(pollingRef.current);

    const interval = setInterval(async () => {
      try {
        const [statusRes, logsRes] = await Promise.all([
          fetch(`${API_BASE}/api/scans/${scanId}/status`),
          fetch(`${API_BASE}/api/scans/${scanId}/logs`),
        ]);
        if (statusRes.ok) {
          const data = await statusRes.json();
          const { status } = data;
          setScanDetails(data);
          if (logsRes.ok) setScanLogs((await logsRes.json()).logs);
          if (status === 'COMPLETED') {
            clearInterval(interval);
            pollingRef.current = null;
            setScanProgress(false);
            setScanMessage('Scan completed successfully.');
            fetchProjectDetails(projId);
            onComplete?.();
          } else if (status === 'FAILED') {
            clearInterval(interval);
            pollingRef.current = null;
            setScanProgress(false);
            setScanMessage('Scan failed. Review diagnostic logs.');
          }
        }
      } catch {
        clearInterval(interval);
        pollingRef.current = null;
        setScanProgress(false);
        setScanMessage('Lost connection during scan polling.');
      }
    }, 1500);

    pollingRef.current = interval;
  }, []);  // fetchProjectDetails is added as dependency below via the definition order

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
        if (detailRes.status === 'fulfilled' && detailRes.value.ok) {
          const projectData = await detailRes.value.json();
          setSelectedProject(projectData);
          
          // Auto-detect and poll any running/pending scan
          if (projectData.latest_scan_id && 
              (projectData.latest_scan_status === 'RUNNING' || projectData.latest_scan_status === 'PENDING')) {
            setScanProgress(true);
            setScanMessage(`Scan in progress (ID: ${projectData.latest_scan_id}). Polling status...`);
            setScanDetails({ current_stage: 'INITIALIZING', overall_progress: 0, stage_status: 'RUNNING' });
            startPolling(projectData.latest_scan_id, projId);
          }
        } else {
          setIsLoading(false);
          return false; // Return false to indicate not found
        }
        
        if (historyRes.status === 'fulfilled' && historyRes.value.ok)
          setVersionHistory(await historyRes.value.json());
      } catch (e) {
        console.error('[SBOMGuard] Failed to load project details', e);
        setIsLoading(false);
        return false;
      }
    }
    setIsLoading(false);
    return true;
  }, [isOfflineMode, startPolling]);

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
        startPolling(scan_id, projId, onComplete);
      } catch (e) {
        setScanProgress(false);
        setScanMessage(`Network error: ${e.message}`);
      }
    }
  }, [isOfflineMode, fetchProjectDetails, startPolling]);

  const triggerGithubRescan = useCallback(async (projId, onComplete) => {
    setScanProgress(true);
    setScanMessage('Contacting GitHub for latest code...');
    setScanLogs('Initiating GitHub re-scan...\n');
    setScanDetails({ current_stage: 'INITIALIZING', overall_progress: 0, stage_status: 'RUNNING' });

    try {
      const r = await fetch(`${API_BASE}/api/scans/github/rescan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projId }),
      });
      if (!r.ok) {
        const errText = await r.text();
        setScanProgress(false);
        setScanMessage(`Error: ${errText}`);
        setScanDetails(null);
        return;
      }
      const { scan_id } = await r.json();
      setScanMessage(`GitHub re-scan initiated (ID: ${scan_id}). Polling status...`);
      startPolling(scan_id, projId, onComplete);
    } catch (e) {
      setScanProgress(false);
      setScanMessage(`Network error: ${e.message}`);
      setScanDetails(null);
    }
  }, [startPolling]);

  const triggerZipRescan = useCallback(async (projId, file, onComplete) => {
    if (!file) return;
    setScanProgress(true);
    setScanMessage('Uploading ZIP archive...');
    setScanLogs('Initiating ZIP upload scan...\n');
    setScanDetails({ current_stage: 'INITIALIZING', overall_progress: 0, stage_status: 'RUNNING' });

    try {
      const formData = new FormData();
      formData.append('project_id', projId);
      formData.append('file', file);

      const r = await fetch(`${API_BASE}/api/scans/upload`, {
        method: 'POST',
        body: formData,
      });
      if (!r.ok) {
        const errText = await r.text();
        setScanProgress(false);
        setScanMessage(`Upload error: ${errText}`);
        setScanDetails(null);
        return;
      }
      const { scan_id } = await r.json();
      setScanMessage(`ZIP scan initiated (ID: ${scan_id}). Polling status...`);
      startPolling(scan_id, projId, onComplete);
    } catch (e) {
      setScanProgress(false);
      setScanMessage(`Network error: ${e.message}`);
      setScanDetails(null);
    }
  }, [startPolling]);

  return {
    isLoading,
    selectedProject, setSelectedProject,
    versionHistory,
    scanProgress, scanMessage, scanLogs, scanDetails,
    setScanMessage, setScanLogs,
    fetchProjectDetails,
    triggerScan,
    triggerGithubRescan,
    triggerZipRescan,
  };
}
