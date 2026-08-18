import { useState, useCallback } from 'react';
import { API_BASE, MOCK_PROJECTS, MOCK_TICKETS, MOCK_AUDIT, MOCK_POLICIES } from '../constants/mock';

/**
 * usePlatformData — manages top-level platform data (projects, tickets, audit, policies).
 * Exposes isLoading + isOfflineMode so pages can render skeletons during fetch.
 */
export function usePlatformData() {
  const [isLoading, setIsLoading] = useState(true);
  const [isOfflineMode, setIsOfflineMode] = useState(false);
  const [projects, setProjects] = useState([]);
  const [tickets, setTickets] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [policies, setPolicies] = useState([]);

  const loadPlatformData = useCallback(async () => {
    setIsLoading(true);
    try {
      const testReq = await fetch(`${API_BASE}/`);
      if (!testReq.ok) throw new Error('Server not responding');

      setIsOfflineMode(false);

      const [projRes, tickRes, auditRes, polRes] = await Promise.allSettled([
        fetch(`${API_BASE}/api/projects`),
        fetch(`${API_BASE}/api/tickets`),
        fetch(`${API_BASE}/api/audit-logs`),
        fetch(`${API_BASE}/api/policies`),
      ]);

      if (projRes.status === 'fulfilled' && projRes.value.ok)
        setProjects(await projRes.value.json());
      if (tickRes.status === 'fulfilled' && tickRes.value.ok)
        setTickets(await tickRes.value.json());
      if (auditRes.status === 'fulfilled' && auditRes.value.ok)
        setAuditLogs(await auditRes.value.json());
      if (polRes.status === 'fulfilled' && polRes.value.ok)
        setPolicies(await polRes.value.json());
    } catch {
      console.log('[SBOMGuard] Server offline — loading mock demo dataset.');
      setIsOfflineMode(true);
      setProjects(MOCK_PROJECTS);
      setTickets(MOCK_TICKETS);
      setAuditLogs(MOCK_AUDIT);
      setPolicies(MOCK_POLICIES);
    } finally {
      setIsLoading(false);
    }
  }, []);

  return {
    isLoading,
    isOfflineMode,
    projects, setProjects,
    tickets, setTickets,
    auditLogs, setAuditLogs,
    policies, setPolicies,
    loadPlatformData,
  };
}
