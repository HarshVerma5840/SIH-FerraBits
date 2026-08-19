import React, { useState, useEffect, useCallback } from 'react';
import {
  Bug, ExternalLink, ChevronDown, ChevronRight, Shield,
  AlertTriangle, Info, Zap, Database, Sparkles, BookOpen,
  ArrowRight, CheckCircle2, Lock, Hash, GitBranch, BarChart2,
  RefreshCw, Filter,
} from 'lucide-react';
import { API_BASE } from '../../constants/mock';
import { Spinner } from '../../components/Loader';
import WhyRiskyCard from './WhyRiskyCard';

// ─── Design tokens ────────────────────────────────────────────────────────────
const SEV_COLORS = {
  CRITICAL: { bg: 'rgba(239,68,68,0.12)',   border: '#ef4444', text: '#ef4444',  glow: 'rgba(239,68,68,0.35)' },
  HIGH:     { bg: 'rgba(249,115,22,0.12)',  border: '#f97316', text: '#f97316',  glow: 'rgba(249,115,22,0.30)' },
  MEDIUM:   { bg: 'rgba(234,179,8,0.12)',   border: '#eab308', text: '#eab308',  glow: 'rgba(234,179,8,0.25)' },
  LOW:      { bg: 'rgba(34,197,94,0.12)',   border: '#22c55e', text: '#22c55e',  glow: 'rgba(34,197,94,0.25)' },
  UNKNOWN:  { bg: 'rgba(100,116,139,0.12)', border: '#64748b', text: '#94a3b8',  glow: 'transparent' },
};

// Panel accent colours — each data-type category gets a unique palette
const PANEL_THEMES = {
  facts:    { accent: '#6366f1', dim: 'rgba(99,102,241,0.08)',   label: 'VERIFIED INTELLIGENCE',  labelColor: '#818cf8' },
  version:  { accent: '#0ea5e9', dim: 'rgba(14,165,233,0.08)',   label: 'VERSION EVIDENCE',        labelColor: '#38bdf8' },
  risk:     { accent: '#f97316', dim: 'rgba(249,115,22,0.06)',   label: 'SBOMGUARD ANALYSIS',      labelColor: '#fb923c' },
  ai:       { accent: '#a855f7', dim: 'rgba(168,85,247,0.06)',   label: 'AI EXPLANATION',          labelColor: '#c084fc' },
};

// ─── Reusable atoms ───────────────────────────────────────────────────────────
function SeverityBadge({ severity, large }) {
  const s = (severity || 'UNKNOWN').toUpperCase();
  const c = SEV_COLORS[s] || SEV_COLORS.UNKNOWN;
  return (
    <span style={{
      fontSize: large ? '0.75rem' : '0.68rem', fontWeight: 700, letterSpacing: '0.06em',
      padding: large ? '4px 10px' : '2px 8px', borderRadius: '5px',
      background: c.bg, border: `1px solid ${c.border}60`, color: c.text,
    }}>
      {s}
    </span>
  );
}

function Mono({ children, color }) {
  return (
    <span style={{ fontFamily: 'var(--font-mono)', color: color || 'inherit' }}>{children}</span>
  );
}

function KV({ label, value, mono, color, children }) {
  return (
    <div>
      <div style={{ fontSize: '0.67rem', color: 'var(--text-muted)', fontWeight: 700, letterSpacing: '0.05em', marginBottom: '3px' }}>
        {label}
      </div>
      <div style={{ fontSize: '0.82rem', color: color || 'white', fontWeight: 500 }}>
        {children || (mono ? <Mono color={color}>{value}</Mono> : value || '—')}
      </div>
    </div>
  );
}

function PanelHeader({ icon: Icon, theme, children, right }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: '8px',
      padding: '10px 14px', borderBottom: `1px solid ${theme.accent}20`,
      background: theme.dim,
    }}>
      <Icon size={13} color={theme.accent} />
      <span style={{ fontSize: '0.67rem', fontWeight: 800, letterSpacing: '0.1em', color: theme.labelColor }}>
        {theme.label}
      </span>
      {right && <div style={{ marginLeft: 'auto' }}>{right}</div>}
    </div>
  );
}

function SourceChip({ source }) {
  const colors = {
    OSV:        { bg: 'rgba(99,102,241,0.15)', border: '#6366f1', text: '#818cf8' },
    OFFLINE_DB: { bg: 'rgba(251,191,36,0.10)', border: '#fbbf24', text: '#fbbf24' },
  };
  const c = colors[source] || colors.OFFLINE_DB;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      fontSize: '0.65rem', fontWeight: 700, padding: '2px 7px', borderRadius: '4px',
      background: c.bg, border: `1px solid ${c.border}60`, color: c.text,
    }}>
      <Database size={9} />
      {source || 'UNKNOWN'}
    </span>
  );
}

function ConfidenceBar({ level }) {
  const map = { HIGH: { w: '100%', color: '#22c55e' }, MEDIUM: { w: '60%', color: '#eab308' }, LOW: { w: '30%', color: '#f97316' }, UNKNOWN: { w: '15%', color: '#64748b' } };
  const m = map[level] || map.UNKNOWN;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <div style={{ flex: 1, height: '4px', borderRadius: '2px', background: 'rgba(255,255,255,0.07)' }}>
        <div style={{ width: m.w, height: '100%', borderRadius: '2px', background: m.color, transition: 'width 0.4s' }} />
      </div>
      <span style={{ fontSize: '0.7rem', fontWeight: 700, color: m.color, minWidth: 52 }}>{level}</span>
    </div>
  );
}

// ─── Card: Security Facts ─────────────────────────────────────────────────────
function SecurityFactsCard({ vulnerability, component }) {
  const t = PANEL_THEMES.facts;
  const sevColor = (SEV_COLORS[(vulnerability?.severity || 'UNKNOWN').toUpperCase()] || SEV_COLORS.UNKNOWN);

  return (
    <div style={{ borderRadius: '10px', border: `1px solid ${t.accent}25`, overflow: 'hidden' }}>
      <PanelHeader icon={Database} theme={t}
        right={<SourceChip source={vulnerability?.source} />}
      />
      <div style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '14px' }}>

        {/* CVE + severity headline */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <Mono color='white'><strong style={{ fontSize: '0.95rem' }}>{vulnerability?.id || 'UNKNOWN'}</strong></Mono>
              {(vulnerability?.aliases || []).slice(0, 2).map((a, i) => (
                <Mono key={i} color='var(--text-muted)' style={{ fontSize: '0.72rem' }}>{a}</Mono>
              ))}
            </div>
            {vulnerability?.summary && (
              <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: 1.55 }}>
                {vulnerability.summary}
              </p>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px', flexShrink: 0 }}>
            <div style={{
              fontSize: '1.6rem', fontWeight: 800, color: sevColor.text,
              lineHeight: 1, textShadow: `0 0 18px ${sevColor.glow}`,
            }}>
              {vulnerability?.cvss != null ? vulnerability.cvss.toFixed(1) : '?'}
            </div>
            <div style={{ fontSize: '0.58rem', color: 'var(--text-muted)', fontWeight: 700 }}>CVSS</div>
            <SeverityBadge severity={vulnerability?.severity} />
          </div>
        </div>

        <div style={{ height: '1px', background: `${t.accent}15` }} />

        {/* Version grids */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <KV label="AFFECTED VERSIONS">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px', marginTop: '4px' }}>
              {(vulnerability?.affected_versions || []).length === 0 ? (
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Not specified</span>
              ) : (
                (vulnerability.affected_versions || []).slice(0, 6).map((v, i) => (
                  <span key={i} style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
                    background: 'rgba(239,68,68,0.10)', border: '1px solid rgba(239,68,68,0.25)',
                    padding: '1px 6px', borderRadius: '4px', color: '#fca5a5',
                  }}>{v}</span>
                ))
              )}
            </div>
          </KV>

          <KV label="FIXED IN">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
              {(vulnerability?.fixed_versions || []).length === 0 ? (
                <span style={{ fontSize: '0.75rem', color: '#f97316' }}>No fix available</span>
              ) : (
                (vulnerability.fixed_versions || []).slice(0, 3).map((v, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ArrowRight size={10} color='#22c55e' />
                    <Mono color='#4ade80'><strong>{v}</strong></Mono>
                  </div>
                ))
              )}
            </div>
          </KV>
        </div>

        {/* Exploit status */}
        {vulnerability?.exploit_status === 'KNOWN' && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '8px 10px', borderRadius: '6px',
            background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.35)',
          }}>
            <Zap size={13} color='#ef4444' />
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#ef4444' }}>
              Known Active Exploit — treat as highest priority
            </span>
          </div>
        )}

        {/* Source link */}
        {vulnerability?.source_url && (
          <a href={vulnerability.source_url} target="_blank" rel="noopener noreferrer"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '0.73rem', color: '#818cf8', textDecoration: 'none' }}>
            <ExternalLink size={11} />
            View on {vulnerability?.source || 'OSV'}
          </a>
        )}
      </div>
    </div>
  );
}

// ─── Card: Version Evidence & Supply Chain Anomaly ───────────────────────────
function VersionEvidenceCard({ component, anomaly }) {
  const t = PANEL_THEMES.version;
  const conf = (component?.version_confidence || 'UNKNOWN').toUpperCase();

  return (
    <div style={{ borderRadius: '10px', border: `1px solid ${t.accent}25`, overflow: 'hidden' }}>
      <PanelHeader icon={Hash} theme={t} />
      <div style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '14px' }}>

        {/* Identity block */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: 42, height: 42, borderRadius: '8px', flexShrink: 0,
            background: `${t.accent}15`, border: `1px solid ${t.accent}30`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <BookOpen size={18} color={t.accent} />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.92rem' }}>{component?.name || 'UNKNOWN'}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#38bdf8', marginTop: '2px' }}>
              {component?.version || 'UNKNOWN'}
            </div>
          </div>
        </div>

        <div style={{ height: '1px', background: `${t.accent}15` }} />

        <KV label="INSTALLED VERSION">
          <Mono color='white'><strong style={{ fontSize: '0.95rem' }}>{component?.version || 'UNKNOWN'}</strong></Mono>
        </KV>

        <KV label="VERSION SOURCE">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
            {component?.version_source === 'lockfile' ? <Lock size={12} color={t.accent} /> : <GitBranch size={12} color={t.accent} />}
            <span style={{ fontWeight: 600, fontSize: '0.82rem', color: '#38bdf8' }}>
              {(component?.version_source || 'UNKNOWN').toUpperCase()}
            </span>
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '3px' }}>
            {component?.version_source === 'lockfile'
              ? 'Exact version pinned from lock file — high confidence identity'
              : component?.version_source === 'manifest'
              ? 'Version from manifest — may be a range, not pinned'
              : 'Version origin could not be determined'}
          </div>
        </KV>

        <KV label="DETECTION CONFIDENCE">
          <div style={{ marginTop: '4px' }}>
            <ConfidenceBar level={conf} />
          </div>
        </KV>

        {component?.purl && (
          <KV label="PACKAGE URL (PURL)">
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
              wordBreak: 'break-all', color: 'var(--text-muted)', marginTop: '2px',
              padding: '6px 8px', borderRadius: '5px', background: 'rgba(255,255,255,0.03)',
              border: '1px solid var(--border-color)',
            }}>
              {component.purl}
            </div>
          </KV>
        )}

        {/* Phase 5: Prototype Anomaly Signal */}
        {anomaly && (
          <>
            <div style={{ height: '1px', background: `${t.accent}15` }} />
            <div style={{
              background: 'rgba(239, 68, 68, 0.04)',
              border: '1px solid rgba(239, 68, 68, 0.2)',
              borderRadius: '8px', padding: '12px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ fontSize: '0.67rem', fontWeight: 700, color: '#fca5a5', letterSpacing: '0.06em', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <AlertTriangle size={12} color="#f87171" />
                  SUPPLY CHAIN ANOMALY
                </div>
                <div style={{
                  fontSize: '0.58rem', fontWeight: 800, color: '#f87171',
                  background: 'rgba(239, 68, 68, 0.15)', padding: '2px 6px',
                  borderRadius: '4px', border: '1px solid rgba(239, 68, 68, 0.4)'
                }}>
                  PROTOTYPE SIGNAL
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <span style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f87171' }}>{anomaly.score}</span>
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>/ 100</span>
                <span style={{
                  fontSize: '0.68rem', fontWeight: 700, color: anomaly.classification === 'SUSPICIOUS' ? '#ef4444' : '#eab308',
                  marginLeft: 'auto'
                }}>
                  {anomaly.classification}
                </span>
              </div>
              <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                {(anomaly.signals || []).map((s, i) => (
                  <li key={i} style={{ marginBottom: '4px' }}>{s}</li>
                ))}
                {(anomaly.signals || []).length === 0 && (
                  <li style={{ color: 'var(--text-muted)' }}>No notable anomalies.</li>
                )}
              </ul>
              <div style={{ fontSize: '0.6rem', color: '#ef4444', marginTop: '10px', fontStyle: 'italic', opacity: 0.8 }}>
                Note: This is an anomaly signal only, not proof of malicious behavior.
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Card: Why This Matters (Risk Analysis wrapper) ───────────────────────────
function RiskAnalysisCard({ risk }) {
  const t = PANEL_THEMES.risk;
  const sevColor = SEV_COLORS[(risk?.severity || 'UNKNOWN').toUpperCase()] || SEV_COLORS.UNKNOWN;
  const score = risk?.score ?? 0;
  const topFactors = (risk?.factors || []).filter(f => (f.points || 0) > 0).slice(0, 3);

  return (
    <div style={{ borderRadius: '10px', border: `1px solid ${t.accent}25`, overflow: 'hidden' }}>
      <PanelHeader icon={BarChart2} theme={t} />
      <div style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '14px' }}>

        {/* Score + level */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ position: 'relative', flexShrink: 0 }}>
            <svg width={72} height={72} style={{ transform: 'rotate(-90deg)' }}>
              <circle cx={36} cy={36} r={28} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={7} />
              <circle cx={36} cy={36} r={28} fill="none"
                stroke={sevColor.border} strokeWidth={7}
                strokeDasharray={2 * Math.PI * 28}
                strokeDashoffset={2 * Math.PI * 28 * (1 - score / 100)}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 0.6s ease' }}
              />
            </svg>
            <div style={{
              position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
            }}>
              <span style={{ fontSize: '1.05rem', fontWeight: 800, color: sevColor.text, lineHeight: 1 }}>{score}</span>
              <span style={{ fontSize: '0.48rem', fontWeight: 800, color: sevColor.text, letterSpacing: '0.05em' }}>/100</span>
            </div>
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '4px' }}>RISK LEVEL</div>
            <SeverityBadge severity={risk?.severity} large />
            {risk?.calculation_version && (
              <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
                {risk.calculation_version}
              </div>
            )}
          </div>
        </div>

        {/* Top factors summary */}
        {topFactors.length > 0 && (
          <>
            <div style={{ height: '1px', background: `${t.accent}15` }} />
            <div>
              <div style={{ fontSize: '0.67rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.06em', marginBottom: '8px' }}>
                TOP CONTRIBUTING FACTORS
              </div>
              {topFactors.map((f, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '7px',
                }}>
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f97316' : '#eab308',
                  }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '0.76rem', fontWeight: 600 }}>{f.title}</div>
                    {f.evidence && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.66rem', color: '#fb923c', marginTop: '1px' }}>
                        {f.evidence}
                      </div>
                    )}
                  </div>
                  <div style={{
                    fontSize: '0.62rem', fontWeight: 700, color: '#fb923c',
                    background: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.25)',
                    padding: '1px 5px', borderRadius: '3px', flexShrink: 0,
                  }}>
                    +{f.points}pt
                  </div>
                </div>
              ))}
              {(risk?.factors || []).length > 3 && (
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  +{(risk.factors || []).length - 3} more factors — expand "Why Is This Risky?" below
                </div>
              )}
            </div>
          </>
        )}

        {/* WhyRiskyCard full detail */}
        <WhyRiskyCard risk={risk} />
      </div>
    </div>
  );
}

// ─── Card: AI Explanation ─────────────────────────────────────────────────────
function AIExplanationPanel({ findingId }) {
  const t = PANEL_THEMES.ai;
  const [state, setState] = useState('idle');
  const [explanation, setExplanation] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    if (state === 'loading' || state === 'done') return;
    setState('loading');
    try {
      const res = await fetch(
        `${API_BASE}/api/vulnerabilities/findings/${findingId}/explain`,
        { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setExplanation(data);
      setState('done');
    } catch (e) {
      setError(e.message);
      setState('error');
    }
  }, [findingId, state]);

  return (
    <div style={{ borderRadius: '10px', border: `1px solid ${t.accent}25`, overflow: 'hidden' }}>
      <PanelHeader icon={Sparkles} theme={t}
        right={
          explanation && (
            <span style={{
              fontSize: '0.6rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px',
              background: explanation.generated_by === 'GEMINI' ? 'rgba(99,102,241,0.2)' : 'rgba(100,116,139,0.15)',
              border: explanation.generated_by === 'GEMINI' ? '1px solid #6366f1' : '1px solid #475569',
              color: explanation.generated_by === 'GEMINI' ? '#818cf8' : '#94a3b8',
            }}>
              {explanation.generated_by === 'GEMINI' ? '✦ Gemini AI' : '⊡ Deterministic'}
            </span>
          )
        }
      />
      <div style={{ padding: '14px' }}>
        {state === 'idle' && (
          <div style={{ textAlign: 'center', padding: '20px 0' }}>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
              Plain-language developer explanation with remediation guidance.
              <br />
              <span style={{ fontSize: '0.7rem', color: '#64748b' }}>AI never determines security facts — only explains them.</span>
            </p>
            <button onClick={load} style={{
              padding: '8px 18px', borderRadius: '8px', border: `1px solid ${t.accent}50`,
              background: `${t.accent}15`, color: '#c084fc', cursor: 'pointer',
              fontSize: '0.78rem', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '6px',
            }}>
              <Sparkles size={13} />
              Generate Explanation
            </button>
          </div>
        )}

        {state === 'loading' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '20px 0', justifyContent: 'center' }}>
            <div style={{
              width: 16, height: 16, borderRadius: '50%',
              border: `2px solid ${t.accent}40`, borderTopColor: t.accent,
              animation: 'spin 0.7s linear infinite'
            }} />
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Generating explanation…</span>
          </div>
        )}

        {state === 'error' && (
          <div style={{
            padding: '12px', borderRadius: '6px',
            background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
            fontSize: '0.75rem', color: '#fca5a5',
            display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            <AlertTriangle size={13} />
            Failed to load explanation: {error}
          </div>
        )}

        {state === 'done' && explanation && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {/* Plain language */}
            <div style={{ borderLeft: `3px solid ${t.accent}`, paddingLeft: '12px' }}>
              <div style={{ fontSize: '0.67rem', fontWeight: 700, color: '#c084fc', letterSpacing: '0.06em', marginBottom: '5px' }}>
                PLAIN-LANGUAGE EXPLANATION
              </div>
              <p style={{ fontSize: '0.82rem', lineHeight: 1.65, color: 'var(--text-secondary)' }}>
                {explanation.plain_language_explanation}
              </p>
            </div>

            {/* Technical detail */}
            {explanation.technical_explanation && (
              <div style={{ borderLeft: '3px solid #0ea5e9', paddingLeft: '12px' }}>
                <div style={{ fontSize: '0.67rem', fontWeight: 700, color: '#38bdf8', letterSpacing: '0.06em', marginBottom: '5px' }}>
                  TECHNICAL DETAIL
                </div>
                <p style={{ fontSize: '0.8rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                  {explanation.technical_explanation}
                </p>
              </div>
            )}

            {/* Recommended action */}
            {explanation.recommended_fix && (
              <div style={{
                display: 'flex', gap: '10px', padding: '10px 12px',
                background: 'rgba(34,197,94,0.07)', border: '1px solid rgba(34,197,94,0.25)',
                borderRadius: '8px',
              }}>
                <CheckCircle2 size={16} color='#22c55e' style={{ marginTop: 2, flexShrink: 0 }} />
                <div>
                  <div style={{ fontSize: '0.67rem', fontWeight: 700, color: '#4ade80', letterSpacing: '0.06em', marginBottom: '4px' }}>
                    RECOMMENDED ACTION
                  </div>
                  <p style={{ fontSize: '0.8rem', color: '#86efac', lineHeight: 1.6 }}>
                    {explanation.recommended_fix}
                  </p>
                </div>
              </div>
            )}

            {/* Verification steps */}
            {(explanation.verification_steps || []).length > 0 && (
              <div>
                <div style={{ fontSize: '0.67rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.06em', marginBottom: '8px' }}>
                  VERIFICATION STEPS
                </div>
                {explanation.verification_steps.map((step, i) => (
                  <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '6px' }}>
                    <span style={{
                      width: 18, height: 18, borderRadius: '50%', flexShrink: 0,
                      background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '0.62rem', fontWeight: 800, color: '#c084fc',
                    }}>{i + 1}</span>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>{step}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Confidence */}
            {explanation.confidence && (
              <div style={{
                fontSize: '0.65rem', color: 'var(--text-muted)', borderTop: `1px solid ${t.accent}15`,
                paddingTop: '8px', display: 'flex', gap: '8px', alignItems: 'center',
              }}>
                <Info size={11} />
                Confidence: <strong style={{ color: '#c084fc' }}>{explanation.confidence}</strong>
                <span style={{ marginLeft: 'auto', fontStyle: 'italic' }}>AI explanation — security facts are authoritative</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Expanded finding detail panel ────────────────────────────────────────────
function FindingDetail({ finding }) {
  const { component, vulnerability, risk, status } = finding;
  const sevColor = SEV_COLORS[(vulnerability?.severity || 'UNKNOWN').toUpperCase()] || SEV_COLORS.UNKNOWN;

  return (
    <div style={{
      padding: '0',
      background: 'rgba(0,0,0,0.15)',
      borderBottom: '1px solid var(--border-color)',
    }}>
      {/* Finding header bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap',
        padding: '14px 20px',
        borderBottom: `1px solid ${sevColor.border}25`,
        background: sevColor.bg,
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.9rem', color: 'white' }}>
              {component?.name}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: sevColor.text }}>
              @{component?.version}
            </span>
            <SeverityBadge severity={vulnerability?.severity} large />
            {vulnerability?.exploit_status === 'KNOWN' && (
              <span style={{
                background: 'rgba(239,68,68,0.25)', color: '#ef4444',
                fontSize: '0.62rem', fontWeight: 800, padding: '2px 7px',
                borderRadius: '4px', border: '1px solid rgba(239,68,68,0.6)',
                display: 'flex', alignItems: 'center', gap: '4px',
              }}>
                <Zap size={10} />EXPLOIT KNOWN
              </span>
            )}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            {vulnerability?.id} · Risk Score: <strong style={{ color: sevColor.text }}>{risk?.score ?? '?'}/100</strong>
          </div>
        </div>
        <div style={{
          padding: '6px 14px', borderRadius: '6px', fontSize: '0.72rem', fontWeight: 700,
          background: status === 'AFFECTED' ? 'rgba(249,115,22,0.15)' : 'rgba(34,197,94,0.1)',
          border: `1px solid ${status === 'AFFECTED' ? 'rgba(249,115,22,0.4)' : 'rgba(34,197,94,0.4)'}`,
          color: status === 'AFFECTED' ? '#f97316' : '#22c55e',
        }}>
          {status || 'AFFECTED'}
        </div>
      </div>

      {/* 4-card grid */}
      <div style={{
        padding: '16px 20px',
        display: 'grid',
        gridTemplateColumns: 'repeat(2, 1fr)',
        gap: '14px',
      }}>
        <SecurityFactsCard vulnerability={vulnerability} component={component} />
        <VersionEvidenceCard component={component} anomaly={finding.anomaly} />
        <RiskAnalysisCard risk={risk} />
        <AIExplanationPanel findingId={finding.finding_id} />
      </div>
    </div>
  );
}

// ─── Table row ────────────────────────────────────────────────────────────────
function FindingRow({ finding }) {
  const [open, setOpen] = useState(false);
  const { component, vulnerability, risk, status } = finding;
  const sevColor = SEV_COLORS[(vulnerability?.severity || 'UNKNOWN').toUpperCase()] || SEV_COLORS.UNKNOWN;
  const isExploit = vulnerability?.exploit_status === 'KNOWN';

  return (
    <>
      <tr
        onClick={() => setOpen(p => !p)}
        style={{
          borderBottom: open ? 'none' : '1px solid var(--border-color)',
          cursor: 'pointer', transition: 'background 0.12s',
          background: open ? 'rgba(255,255,255,0.02)' : 'transparent',
        }}
        onMouseEnter={e => !open && (e.currentTarget.style.background = 'rgba(255,255,255,0.025)')}
        onMouseLeave={e => !open && (e.currentTarget.style.background = 'transparent')}
      >
        {/* Toggle */}
        <td style={{ padding: '13px 8px 13px 16px', width: 22 }}>
          <div style={{
            width: 18, height: 18, borderRadius: '4px',
            border: `1px solid ${open ? sevColor.border : 'var(--border-color)'}`,
            background: open ? sevColor.bg : 'transparent',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: open ? sevColor.text : 'var(--text-muted)',
          }}>
            {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
          </div>
        </td>

        {/* Severity indicator */}
        <td style={{ padding: '13px 10px', width: 4 }}>
          <div style={{ width: 4, height: 28, borderRadius: '2px', background: sevColor.border, boxShadow: `0 0 6px ${sevColor.glow}` }} />
        </td>

        {/* CVE */}
        <td style={{ padding: '13px 12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', flexWrap: 'wrap' }}>
            <Mono color='white'><strong style={{ fontSize: '0.82rem' }}>{vulnerability?.id || 'UNKNOWN'}</strong></Mono>
            {isExploit && (
              <span style={{
                background: 'rgba(239,68,68,0.2)', color: '#ef4444',
                fontSize: '0.57rem', fontWeight: 800, padding: '1px 5px',
                borderRadius: '3px', border: '1px solid rgba(239,68,68,0.5)',
              }}>EXPLOIT</span>
            )}
          </div>
          {(vulnerability?.aliases || []).length > 0 && (
            <div style={{ fontSize: '0.62rem', color: 'var(--text-muted)', marginTop: '2px' }}>
              {vulnerability.aliases.slice(0, 1).join(', ')}
            </div>
          )}
        </td>

        {/* Component */}
        <td style={{ padding: '13px 12px' }}>
          <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{component?.name}</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginTop: '2px' }}>
            <Mono color='var(--text-muted)'><span style={{ fontSize: '0.73rem' }}>{component?.version}</span></Mono>
            {component?.version_source && (
              <span style={{
                fontSize: '0.58rem', fontWeight: 700, padding: '0 5px',
                background: component.version_source === 'lockfile' ? 'rgba(14,165,233,0.15)' : 'rgba(100,116,139,0.1)',
                border: `1px solid ${component.version_source === 'lockfile' ? 'rgba(14,165,233,0.3)' : 'rgba(100,116,139,0.2)'}`,
                borderRadius: '3px', color: component.version_source === 'lockfile' ? '#38bdf8' : '#94a3b8',
              }}>
                {component.version_source.toUpperCase()}
              </span>
            )}
          </div>
        </td>

        {/* Ecosystem */}
        <td style={{ padding: '13px 12px' }}>
          <span style={{
            fontSize: '0.72rem', background: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.08)',
            padding: '3px 8px', borderRadius: '4px',
          }}>{component?.ecosystem || '—'}</span>
        </td>

        {/* Severity + CVSS */}
        <td style={{ padding: '13px 12px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <SeverityBadge severity={vulnerability?.severity} />
            {vulnerability?.cvss != null && (
              <span style={{ fontSize: '0.68rem', color: sevColor.text, fontWeight: 700 }}>
                CVSS {vulnerability.cvss.toFixed(1)}
              </span>
            )}
          </div>
        </td>

        {/* Risk score */}
        <td style={{ padding: '13px 12px' }}>
          <div style={{ fontWeight: 800, fontSize: '0.88rem', color: sevColor.text }}>
            {risk?.score ?? '—'}
          </div>
          <div style={{ fontSize: '0.62rem', color: 'var(--text-muted)' }}>/100</div>
        </td>

        {/* Fix */}
        <td style={{ padding: '13px 12px' }}>
          {(vulnerability?.fixed_versions || []).length > 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <ArrowRight size={10} color='#22c55e' />
              <Mono color='#4ade80' style={{ fontSize: '0.75rem' }}>{vulnerability.fixed_versions[0]}</Mono>
            </div>
          ) : (
            <span style={{ fontSize: '0.7rem', color: '#f97316' }}>No fix</span>
          )}
        </td>

        {/* Source */}
        <td style={{ padding: '13px 16px' }}>
          <SourceChip source={vulnerability?.source} />
        </td>
      </tr>

      {open && (
        <tr>
          <td colSpan={9} style={{ padding: 0 }}>
            <FindingDetail finding={finding} />
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
              id: v.cve_id, aliases: [], summary: v.description,
              severity: v.severity, cvss: v.cvss_score,
              affected_versions: [], fixed_versions: [],
              exploit_status: 'UNKNOWN', source: 'OFFLINE_DB',
              source_url: `https://nvd.nist.gov/vuln/detail/${v.cve_id}`,
            },
            environment_context: { environment: 'UNKNOWN', internet_exposed: 'unknown', business_criticality: 'UNKNOWN' },
            risk: { score: c.risk_score, severity: c.risk_level, factors: [], missing_signals: [], calculation_version: 'offline' },
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

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    const s = (f.vulnerability?.severity || '').toUpperCase();
    if (s in counts) counts[s]++;
  }

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* Page header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Bug size={22} color="#818cf8" />
            Vulnerability Intelligence
          </h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Verified OSV findings · Deterministic risk scoring · AI-assisted explanations
          </p>
          {/* Legend */}
          <div style={{ display: 'flex', gap: '16px', marginTop: '8px', flexWrap: 'wrap' }}>
            {[
              { dot: '#6366f1', label: 'Verified Intelligence' },
              { dot: '#f97316', label: 'SBOMGuard Analysis' },
              { dot: '#a855f7', label: 'AI Explanation' },
            ].map(({ dot, label }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: dot }} />
                {label}
              </div>
            ))}
          </div>
        </div>
        <button
          className="btn-secondary"
          onClick={load}
          style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <RefreshCw size={13} />
          Refresh
        </button>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '12px' }}>
        {[['CRITICAL', '#ef4444'], ['HIGH', '#f97316'], ['MEDIUM', '#eab308'], ['LOW', '#22c55e']].map(([sev, color]) => (
          <div
            key={sev}
            className="glass-panel"
            onClick={() => setFilterSev(filterSev === sev ? 'all' : sev)}
            style={{
              padding: '16px 20px', cursor: 'pointer',
              borderLeft: `3px solid ${filterSev === sev ? color : `${color}40`}`,
              opacity: filterSev !== 'all' && filterSev !== sev ? 0.45 : 1,
              transition: 'opacity 0.2s, border-left-color 0.2s',
            }}
          >
            <div style={{ fontSize: '1.9rem', fontWeight: 800, color, lineHeight: 1 }}>{counts[sev]}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700, marginTop: '4px' }}>{sev}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
          <Filter size={13} color='var(--text-muted)' style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
          <input
            type="text"
            placeholder="Search CVE, package name, or description…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              width: '100%', padding: '9px 14px 9px 30px', borderRadius: '8px',
              background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)',
              color: 'white', fontSize: '0.82rem', boxSizing: 'border-box',
            }}
          />
        </div>
        <select
          value={filterSource}
          onChange={e => setFilterSource(e.target.value)}
          style={{
            padding: '9px 12px', borderRadius: '8px',
            background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)',
            color: 'white', fontSize: '0.82rem',
          }}
        >
          <option value="all">All Sources</option>
          <option value="OSV">OSV API</option>
          <option value="OFFLINE_DB">Offline DB</option>
        </select>
      </div>

      {/* Content */}
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
            <p style={{ marginTop: 8, fontSize: '0.8rem' }}>Scan a project to populate the intelligence database.</p>
          )}
        </div>
      ) : (
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ background: 'rgba(255,255,255,0.025)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ width: 22, padding: '11px 8px 11px 16px' }} />
                <th style={{ width: 4, padding: '11px 0' }} />
                <th style={{ padding: '11px 12px', fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>CVE / ID</th>
                <th style={{ padding: '11px 12px', fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>COMPONENT</th>
                <th style={{ padding: '11px 12px', fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>ECOSYSTEM</th>
                <th style={{ padding: '11px 12px', fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>SEVERITY</th>
                <th style={{ padding: '11px 12px', fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>RISK</th>
                <th style={{ padding: '11px 12px', fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>FIX</th>
                <th style={{ padding: '11px 16px 11px 12px', fontSize: '0.7rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>SOURCE</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <FindingRow key={f.finding_id} finding={f} />
              ))}
            </tbody>
          </table>
          <div style={{
            padding: '10px 16px', fontSize: '0.7rem', color: 'var(--text-muted)',
            borderTop: '1px solid var(--border-color)',
            display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            <Shield size={12} />
            Showing {filtered.length} of {findings.length} findings
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
