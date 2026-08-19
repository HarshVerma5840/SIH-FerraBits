import React, { useState } from 'react';
import { ShieldAlert, ChevronDown, ChevronRight, Info, AlertCircle } from 'lucide-react';

// ── Factor type → colour ───────────────────────────────────────────────────
const TYPE_COLORS = {
  CVSS:         { bg: 'rgba(239,68,68,0.12)',  border: '#ef4444', text: '#fca5a5' },
  EXPLOIT:      { bg: 'rgba(239,68,68,0.18)',  border: '#dc2626', text: '#ef4444' },
  EXPOSURE:     { bg: 'rgba(249,115,22,0.12)', border: '#f97316', text: '#fdba74' },
  BLAST_RADIUS: { bg: 'rgba(234,179,8,0.12)',  border: '#eab308', text: '#fde047' },
  VERSION:      { bg: 'rgba(99,102,241,0.12)', border: '#6366f1', text: '#a5b4fc' },
  DEPTH:        { bg: 'rgba(100,116,139,0.12)',border: '#64748b', text: '#94a3b8' },
  ML_ANOMALY:   { bg: 'rgba(168,85,247,0.12)', border: '#a855f7', text: '#d8b4fe' },
};

const SEV_DOT = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
};

function FactorBar({ points, maxPoints }) {
  if (!maxPoints) return null;
  const pct = Math.min(100, (points / maxPoints) * 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px' }}>
      <div style={{
        flex: 1, height: '4px', borderRadius: '2px',
        background: 'rgba(0,0,0,0.08)'
      }}>
        <div style={{
          width: `${pct}%`, height: '100%', borderRadius: '2px',
          background: pct >= 80 ? '#ef4444' : pct >= 50 ? '#f97316' : '#6366f1',
          transition: 'width 0.4s ease',
        }} />
      </div>
      <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
        {points}/{maxPoints}pt
      </span>
    </div>
  );
}

function FactorCard({ factor }) {
  const colors = TYPE_COLORS[factor.type] || TYPE_COLORS.DEPTH;
  const sevDot = SEV_DOT[factor.severity] || '#64748b';

  return (
    <div style={{
      padding: '10px 12px', borderRadius: '8px',
      background: colors.bg, border: `1px solid ${colors.border}30`,
      display: 'flex', flexDirection: 'column', gap: '4px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        {/* Severity dot */}
        <span style={{
          width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0,
          background: sevDot, boxShadow: `0 0 5px ${sevDot}80`
        }} />
        <span style={{ fontWeight: 700, fontSize: '0.8rem', color: 'var(--text-primary)', flex: 1 }}>
          {factor.title}
        </span>
        <span style={{
          fontSize: '0.62rem', fontWeight: 600, padding: '1px 6px', borderRadius: '4px',
          background: `${colors.border}20`, border: `1px solid ${colors.border}40`, color: colors.text,
        }}>
          {factor.factor || factor.type}
        </span>
      </div>

      <p style={{ fontSize: '0.77rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
        {factor.description}
      </p>

      {factor.evidence && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: colors.text, marginTop: 2 }}>
          ⬥ {factor.evidence}
        </div>
      )}

      {factor.max_points > 0 && (
        <FactorBar points={factor.points} maxPoints={factor.max_points} />
      )}
    </div>
  );
}

function ScoreRing({ score, level }) {
  const COLORS = {
    CRITICAL: '#ef4444',
    HIGH:     '#f97316',
    MEDIUM:   '#eab308',
    LOW:      '#22c55e',
  };
  const color = COLORS[level] || '#64748b';
  const r = 36;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;

  return (
    <div style={{ position: 'relative', width: 90, height: 90, flexShrink: 0 }}>
      <svg width="90" height="90" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="45" cy="45" r={r} fill="none" stroke="rgba(0,0,0,0.06)" strokeWidth="8" />
        <circle cx="45" cy="45" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center', gap: 2
      }}>
        <span style={{ fontSize: '1.2rem', fontWeight: 800, color, lineHeight: 1 }}>{score}</span>
        <span style={{ fontSize: '0.55rem', fontWeight: 700, color, letterSpacing: '0.05em' }}>{level}</span>
      </div>
    </div>
  );
}

/**
 * WhyRiskyCard
 *
 * Displays the explainable Phase 3 risk analysis alongside a SecurityFinding.
 *
 * Props:
 *   risk: {
 *     score, severity, factors: [], missing_signals: [], calculation_version
 *   }
 */
export default function WhyRiskyCard({ risk }) {
  const [showMissing, setShowMissing] = useState(false);

  if (!risk) return null;

  const { score = 0, severity = 'UNKNOWN', factors = [], missing_signals = [], calculation_version } = risk;
  const totalPts = factors.reduce((s, f) => s + (f.points || 0), 0);

  return (
    <div style={{
      borderRadius: '10px',
      border: '1px solid rgba(249,115,22,0.2)',
      background: 'rgba(249,115,22,0.03)',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '14px 16px',
        display: 'flex', alignItems: 'center', gap: '12px',
        borderBottom: '1px solid rgba(249,115,22,0.12)',
      }}>
        <ShieldAlert size={16} color="#f97316" />
        <div style={{ flex: 1 }}>
          <span style={{ fontWeight: 700, fontSize: '0.84rem' }}>Why Is This Risky?</span>
          {calculation_version && (
            <span style={{ marginLeft: 8, fontSize: '0.62rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {calculation_version}
            </span>
          )}
        </div>
        <ScoreRing score={score} level={severity} />
      </div>

      {/* Factors */}
      {factors.length > 0 ? (
        <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', letterSpacing: '0.05em', fontWeight: 700, marginBottom: 2 }}>
            CONTRIBUTING FACTORS — {factors.length} signal{factors.length !== 1 ? 's' : ''} · {totalPts.toFixed(1)} points
          </div>
          {factors
            .filter(f => f.points > 0 || f.type === 'PRODUCTION_EXPOSURE')
            .sort((a, b) => (b.points || 0) - (a.points || 0))
            .map((f, i) => <FactorCard key={i} factor={f} />)
          }
        </div>
      ) : (
        <div style={{ padding: '20px 16px', fontSize: '0.78rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          No scored factors available for this finding.
        </div>
      )}

      {/* Missing signals (collapsible) */}
      {missing_signals.length > 0 && (
        <div style={{ borderTop: '1px solid rgba(249,115,22,0.12)' }}>
          <button
            onClick={() => setShowMissing(p => !p)}
            style={{
              width: '100%', padding: '9px 16px',
              display: 'flex', alignItems: 'center', gap: '8px',
              background: 'rgba(234,179,8,0.05)', border: 'none', cursor: 'pointer',
              color: '#fbbf24', fontSize: '0.73rem', fontWeight: 600, textAlign: 'left',
            }}
          >
            {showMissing ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            <Info size={13} />
            {missing_signals.length} signal{missing_signals.length !== 1 ? 's' : ''} unavailable
            <span style={{ marginLeft: 'auto', fontSize: '0.65rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              unknown ≠ safe
            </span>
          </button>

          {showMissing && (
            <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {missing_signals.map((sig, i) => {
                const [label, ...rest] = sig.split(':');
                return (
                  <div key={i} style={{
                    padding: '8px 10px', borderRadius: '6px',
                    background: 'rgba(234,179,8,0.06)',
                    borderLeft: '3px solid #eab30850',
                    display: 'flex', gap: '8px', alignItems: 'flex-start'
                  }}>
                    <AlertCircle size={12} color="#fbbf24" style={{ marginTop: 2, flexShrink: 0 }} />
                    <div>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', fontWeight: 700, color: '#fbbf24' }}>
                        {label}
                      </span>
                      {rest.length > 0 && (
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 2 }}>
                          {rest.join(':').trim()}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
