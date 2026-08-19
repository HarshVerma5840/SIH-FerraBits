import React, { useState, useEffect, useCallback } from 'react';
import { Bug, ExternalLink, ChevronDown, ChevronRight, Shield, AlertTriangle, Info } from 'lucide-react';
import { API_BASE } from '../../constants/mock';
import { Spinner } from '../../components/Loader';
import AIExplanationCard from './AIExplanationCard';

// ─── Severity badge color mapping ────────────────────────────────────────────
const SEV_COLORS = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)',   border: '#ef4444', text: '#ef4444' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)',  border: '#f97316', text: '#f97316' },
  MEDIUM:   { bg: 'rgba(234,179,8,0.15)',   border: '#eab308', text: '#eab308' },
  LOW:      { bg: 'rgba(34,197,94,0.15)',   border: '#22c55e', text: '#22c55e' },
  UNKNOWN:  { bg: 'rgba(100,116,139,0.15)', border: '#64748b', text: '#64748b' },
};

function SeverityBadge({ severity }) {
  const s = (severity || 'UNKNOWN').toUpperCase();
  const c = SEV_COLORS[s] || SEV_COLORS.UNKNOWN;
  return (
    <span style={{
      fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.05em',
      padding: '3px 8px', borderRadius: '4px',
      background: c.bg, border: `1px solid ${c.border}`, color: c.text,
    }}>
      {s}
    </span>
  );
}

function SourceBadge({ source }) {
  const colors = {
    OSV: { bg: 'rgba(99,102,241,0.15)', border: '#6366f1', text: '#818cf8' },
    OFFLINE_DB: { bg: 'rgba(251,191,36,0.1)', border: '#fbbf24', text: '#fbbf24' },
  };
  const c = colors[source] || colors.OFFLINE_DB;
  return (
    <span style={{
      fontSize: '0.65rem', fontWeight: 600, padding: '2px 6px', borderRadius: '4px',
      background: c.bg, border: `1px solid ${c.border}`, color: c.text,
    }}>
      {source || 'UNKNOWN'}
    </span>
  );
}

// ─── Single finding row (expandable) ─────────────────────────────────────────
function FindingRow({ finding }) {
  const [open, setOpen] = useState(false);
  const { component, vulnerability, risk, environment_context, status } = finding;
  const vulnId = vulnerability?.id || 'UNKNOWN';
  const isKnownExploit = vulnerability?.exploit_status === 'KNOWN';

  return (
    <>
      <tr
        onClick={() => setOpen(p => !p)}
        style={{
          borderBottom: '1px solid var(--border-color)', cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        {/* Expand toggle */}
        <td style={{ padding: '14px 10px 14px 16px', width: 24 }}>
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </td>

        {/* Vuln ID */}
        <td style={{ padding: '14px 12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 600 }}>
              {vulnId}
            </span>
            {isKnownExploit && (
              <span title="Known active exploit" style={{
                background: 'rgba(239,68,68,0.2)', color: '#ef4444',
                fontSize: '0.6rem', fontWeight: 700, padding: '1px 5px', borderRadius: '4px',
                border: '1px solid #ef4444'
              }}>EXPLOIT</span>
            )}
          </div>
          {vulnerability?.aliases?.length > 0 && (
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '3px' }}>
              {vulnerability.aliases.slice(0, 2).join(', ')}
            </div>
          )}
        </td>

        {/* Component */}
        <td style={{ padding: '14px 12px' }}>
          <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{component?.name}</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
            {component?.version}
            {component?.version_source && (
              <span style={{ marginLeft: 6, fontSize: '0.65rem', opacity: 0.7 }}>
                [{component.version_source.toUpperCase()}]
              </span>
            )}
          </div>
        </td>

        {/* Ecosystem */}
        <td style={{ padding: '14px 12px' }}>
          <span style={{
            fontSize: '0.75rem', background: 'rgba(255,255,255,0.05)',
            padding: '3px 8px', borderRadius: '4px'
          }}>{component?.ecosystem}</span>
        </td>

        {/* Severity + CVSS */}
        <td style={{ padding: '14px 12px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <SeverityBadge severity={vulnerability?.severity} />
            {vulnerability?.cvss != null && (
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                CVSS {vulnerability.cvss.toFixed(1)}
              </span>
            )}
          </div>
        </td>

        {/* Fixed version */}
        <td style={{ padding: '14px 12px' }}>
          {vulnerability?.fixed_versions?.length > 0 ? (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#22c55e' }}>
              → {vulnerability.fixed_versions[0]}
            </span>
          ) : (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>N/A</span>
          )}
        </td>

        {/* Source */}
        <td style={{ padding: '14px 12px' }}>
          <SourceBadge source={vulnerability?.source} />
        </td>

        {/* Status */}
        <td style={{ padding: '14px 16px' }}>
          <span style={{
            fontSize: '0.7rem', fontWeight: 600,
            color: status === 'AFFECTED' ? '#f97316' : '#22c55e'
          }}>{status}</span>
        </td>
      </tr>

      {/* Expanded detail panel */}
      {open && (
        <tr>
          <td colSpan={8} style={{ padding: 0 }}>
            <div style={{
              padding: '20px 24px', background: 'rgba(99,102,241,0.03)',
              borderBottom: '1px solid var(--border-color)',
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px',
            }}>
              {/* Left: Vuln details */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <AIExplanationCard findingId={finding.finding_id} inline={false} />

                <div>
                  <h5 style={{ fontSize: '0.8rem', fontWeight: 700, marginBottom: '8px', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                    VULNERABILITY SUMMARY
                  </h5>
                  <p style={{ fontSize: '0.82rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                    {vulnerability?.summary || 'No description available.'}
                  </p>
                </div>

                <div>
                  <h5 style={{ fontSize: '0.8rem', fontWeight: 700, marginBottom: '8px', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                    AFFECTED VERSIONS
                  </h5>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {(vulnerability?.affected_versions || []).slice(0, 8).map((v, i) => (
                      <span key={i} style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
                        background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
                        padding: '2px 8px', borderRadius: '4px', color: '#fca5a5'
                      }}>{v}</span>
                    ))}
                    {(vulnerability?.affected_versions || []).length === 0 && (
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Unknown affected range</span>
                    )}
                  </div>
                </div>

                {vulnerability?.source_url && (
                  <a
                    href={vulnerability.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: '6px',
                      fontSize: '0.75rem', color: 'var(--primary)',
                      textDecoration: 'none'
                    }}
                  >
                    <ExternalLink size={12} />
                    View on {vulnerability?.source || 'OSV'}
                  </a>
                )}
              </div>

              {/* Right: Component identity + context */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '8px', padding: '14px',
                  display: 'flex', flexDirection: 'column', gap: '10px',
                  fontSize: '0.78rem'
                }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Package PURL</span>
                    <div style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: 3, color: 'white' }}>
                      {component?.purl}
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Version Source</span>
                      <div style={{ fontWeight: 600, marginTop: 2 }}>
                        {component?.version_source || 'UNKNOWN'}
                      </div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Confidence</span>
                      <div style={{
                        fontWeight: 600, marginTop: 2,
                        color: component?.version_confidence === 'HIGH' ? '#22c55e'
                          : component?.version_confidence === 'MEDIUM' ? '#eab308'
                          : 'var(--text-muted)'
                      }}>
                        {component?.version_confidence || 'UNKNOWN'}
                      </div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Intel Source</span>
                      <div style={{ fontWeight: 600, marginTop: 2 }}>
                        <SourceBadge source={vulnerability?.source} />
                      </div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Fixed In</span>
                      <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, marginTop: 2, color: '#22c55e' }}>
                        {(vulnerability?.fixed_versions || []).join(', ') || 'N/A'}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Risk factors */}
                {(risk?.factors || []).length > 0 && (
                  <div>
                    <h5 style={{ fontSize: '0.8rem', fontWeight: 700, marginBottom: '8px', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                      WHY IS THIS RISKY?
                    </h5>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {risk.factors.map((factor, idx) => (
                        <div key={idx} style={{
                          padding: '8px 10px', borderRadius: '6px',
                          background: 'rgba(0,0,0,0.2)',
                          borderLeft: `3px solid ${
                            factor.severity === 'CRITICAL' ? '#ef4444'
                              : factor.severity === 'HIGH' ? '#f97316'
                              : '#eab308'
                          }`
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                            <span style={{ fontWeight: 600, fontSize: '0.78rem' }}>{factor.title}</span>
                            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{factor.type}</span>
                          </div>
                          <div style={{ fontSize: '0.7rem', color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
                            {factor.evidence}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function VulnerabilitiesPage({ isOfflineMode }) {
  const [findings, setFindings] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterSev, setFilterSev] = useState('all');
  const [filterSource, setFilterSource] = useState('all');
  const [search, setSearch] = useState('');

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    if (isOfflineMode) {
      // Synthesize offline findings from mock data
      const { MOCK_COMPONENTS } = await import('../../constants/mock');
      const offline = [];
      for (const c of MOCK_COMPONENTS) {
        for (const v of (c.vulnerabilities || [])) {
          offline.push({
            finding_id: `mock-${c.id}-${v.cve_id}`,
            scan_id: 1,
            component: {
              name: c.name, version: c.version, ecosystem: c.ecosystem,
              purl: c.purl, version_source: c.source_file?.includes('lock') ? 'lockfile' : 'manifest',
              version_confidence: c.source_file?.includes('lock') ? 'HIGH' : 'MEDIUM',
            },
            vulnerability: {
              id: v.cve_id,
              aliases: [],
              summary: v.description,
              severity: v.severity,
              cvss: v.cvss_score,
              affected_versions: [],
              fixed_versions: [],
              exploit_status: 'UNKNOWN',
              source: 'OFFLINE_DB',
              source_url: `https://nvd.nist.gov/vuln/detail/${v.cve_id}`,
            },
            environment_context: { environment: 'UNKNOWN', internet_exposed: 'unknown', business_criticality: 'UNKNOWN' },
            risk: { score: c.risk_score, severity: c.risk_level, factors: [] },
            status: 'AFFECTED',
          });
        }
      }
      setFindings(offline);
    } else {
      try {
        const res = await fetch(`${API_BASE}/api/vulnerabilities`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        if (!res.ok) throw new Error(`Server error ${res.status}`);
        setFindings(await res.json());
      } catch (err) {
        setError(err.message);
      }
    }
    setIsLoading(false);
  }, [isOfflineMode]);

  useEffect(() => { load(); }, [load]);

  // ── Filter ──
  const filtered = findings.filter(f => {
    const sev = (f.vulnerability?.severity || '').toUpperCase();
    const src = f.vulnerability?.source || '';
    const q = search.toLowerCase();
    const matchSev = filterSev === 'all' || sev === filterSev;
    const matchSrc = filterSource === 'all' || src === filterSource;
    const matchQ = !q
      || f.vulnerability?.id?.toLowerCase().includes(q)
      || f.component?.name?.toLowerCase().includes(q)
      || f.vulnerability?.summary?.toLowerCase().includes(q);
    return matchSev && matchSrc && matchQ;
  });

  // ── Summary counts ──
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    const s = (f.vulnerability?.severity || '').toUpperCase();
    if (s in counts) counts[s]++;
  }

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Bug size={22} color="#818cf8" />
            Vulnerability Intelligence
          </h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Live security findings from OSV API — no facts generated by AI.
          </p>
        </div>
        <button className="btn-secondary" onClick={load} style={{ fontSize: '0.8rem' }}>
          Refresh
        </button>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '12px' }}>
        {[['CRITICAL','#ef4444'],['HIGH','#f97316'],['MEDIUM','#eab308'],['LOW','#22c55e']].map(([sev, color]) => (
          <div key={sev} className="glass-panel" style={{
            padding: '16px 20px', borderLeft: `3px solid ${color}`,
            cursor: 'pointer',
            opacity: filterSev !== 'all' && filterSev !== sev ? 0.5 : 1,
          }} onClick={() => setFilterSev(filterSev === sev ? 'all' : sev)}>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color }}>{counts[sev]}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginTop: '2px' }}>{sev}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Search by CVE ID, package name, or description…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            flex: 1, minWidth: '240px', padding: '9px 14px', borderRadius: '8px',
            background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', color: 'white',
            fontSize: '0.82rem'
          }}
        />
        <select
          value={filterSource}
          onChange={e => setFilterSource(e.target.value)}
          style={{ padding: '9px 12px', borderRadius: '8px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', color: 'white', fontSize: '0.82rem' }}
        >
          <option value="all">All Sources</option>
          <option value="OSV">OSV API</option>
          <option value="OFFLINE_DB">Offline DB</option>
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
          <Spinner label="Fetching vulnerability intelligence…" />
        </div>
      ) : error ? (
        <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: '#ef4444' }}>
          <AlertTriangle size={32} style={{ marginBottom: 12 }} />
          <p>{error}</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass-panel" style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <Shield size={40} style={{ marginBottom: 12, opacity: 0.4 }} />
          <p>No vulnerability findings match the current filters.</p>
          {findings.length === 0 && (
            <p style={{ marginTop: 8, fontSize: '0.8rem' }}>
              Scan a project to populate the intelligence database.
            </p>
          )}
        </div>
      ) : (
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '12px 10px 12px 16px', width: 24 }} />
                <th style={{ padding: '12px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>CVE / ID</th>
                <th style={{ padding: '12px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>COMPONENT</th>
                <th style={{ padding: '12px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>ECOSYSTEM</th>
                <th style={{ padding: '12px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>SEVERITY / CVSS</th>
                <th style={{ padding: '12px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>FIX VERSION</th>
                <th style={{ padding: '12px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>SOURCE</th>
                <th style={{ padding: '12px 16px 12px 12px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <FindingRow key={f.finding_id} finding={f} />
              ))}
            </tbody>
          </table>
          <div style={{ padding: '10px 16px', fontSize: '0.72rem', color: 'var(--text-muted)', borderTop: '1px solid var(--border-color)' }}>
            Showing {filtered.length} of {findings.length} findings
          </div>
        </div>
      )}
    </div>
  );
}
