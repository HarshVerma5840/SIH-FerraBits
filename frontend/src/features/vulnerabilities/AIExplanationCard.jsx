import React, { useState, useCallback } from 'react';
import { Sparkles, ChevronDown, ChevronRight, AlertCircle, CheckCircle2, Loader2, ExternalLink, Info } from 'lucide-react';
import { API_BASE } from '../../constants/mock';

const CONFIDENCE_COLORS = {
  HIGH:   { color: '#22c55e', label: 'High confidence' },
  MEDIUM: { color: '#eab308', label: 'Medium confidence' },
  LOW:    { color: '#f97316', label: 'Low confidence' },
};

function ConfidencePill({ confidence }) {
  const c = CONFIDENCE_COLORS[confidence] || CONFIDENCE_COLORS.LOW;
  return (
    <span style={{
      fontSize: '0.65rem', fontWeight: 700, padding: '2px 7px', borderRadius: '4px',
      background: `${c.color}20`, border: `1px solid ${c.color}`, color: c.color,
    }}>
      {confidence}
    </span>
  );
}

function GeneratedByBadge({ generatedBy }) {
  const isAI = generatedBy === 'GEMINI';
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      fontSize: '0.62rem', fontWeight: 600, padding: '2px 7px', borderRadius: '4px',
      background: isAI ? 'rgba(99,102,241,0.15)' : 'rgba(100,116,139,0.15)',
      border: isAI ? '1px solid #6366f1' : '1px solid #64748b',
      color: isAI ? '#818cf8' : '#94a3b8',
    }}>
      {isAI ? <Sparkles size={10} /> : <Info size={10} />}
      {isAI ? 'AI-Generated' : 'Deterministic'}
    </span>
  );
}

function Section({ title, children, accent }) {
  return (
    <div style={{
      borderLeft: `3px solid ${accent || 'var(--border-color)'}`,
      paddingLeft: '12px',
    }}>
      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.06em', marginBottom: '6px' }}>
        {title}
      </div>
      <div style={{ fontSize: '0.82rem', lineHeight: 1.65, color: 'var(--text-secondary)' }}>
        {children}
      </div>
    </div>
  );
}

/**
 * AIExplanationCard
 *
 * Shows an inline brief explanation and a toggleable full-detail panel.
 * Calls /api/vulnerabilities/findings/{finding_id}/explain on demand.
 * Falls back gracefully when LLM is unavailable.
 *
 * Props:
 *   findingId  — UUID of the SecurityFinding
 *   inline     — if true shows a compact inline variant; if false shows full card
 */
export default function AIExplanationCard({ findingId, inline = false }) {
  const [state, setState] = useState('idle'); // idle | loading | done | error
  const [explanation, setExplanation] = useState(null);
  const [expanded, setExpanded] = useState(!inline);
  const [error, setError] = useState(null);
  const [llmAvailable, setLlmAvailable] = useState(null);

  const loadExplanation = useCallback(async () => {
    if (state === 'loading' || state === 'done') return;
    setState('loading');
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/api/vulnerabilities/findings/${findingId}/explain`,
        { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }
      );
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setExplanation(data.explanation);
      setLlmAvailable(data.llm_available);
      setState('done');
    } catch (err) {
      setError(err.message);
      setState('error');
    }
  }, [findingId, state]);

  // ── Inline trigger button ──
  if (inline && state === 'idle') {
    return (
      <button
        onClick={loadExplanation}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: '5px',
          fontSize: '0.72rem', fontWeight: 600, padding: '4px 10px',
          borderRadius: '6px', cursor: 'pointer',
          background: 'rgba(99,102,241,0.12)',
          border: '1px solid rgba(99,102,241,0.35)',
          color: '#818cf8', transition: 'all 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.22)'}
        onMouseLeave={e => e.currentTarget.style.background = 'rgba(99,102,241,0.12)'}
      >
        <Sparkles size={12} />
        Explain with AI
      </button>
    );
  }

  if (inline && state === 'loading') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
        <Loader2 size={12} className="animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
        Generating…
      </span>
    );
  }

  // ── Full card ──
  const cardStyle = {
    borderRadius: '10px',
    border: '1px solid rgba(99,102,241,0.25)',
    background: 'rgba(99,102,241,0.04)',
    overflow: 'hidden',
  };

  const headerStyle = {
    padding: '12px 16px',
    display: 'flex', alignItems: 'center', gap: '10px',
    cursor: inline ? 'pointer' : 'default',
    borderBottom: expanded ? '1px solid rgba(99,102,241,0.15)' : 'none',
  };

  if (state === 'idle') {
    return (
      <div style={cardStyle}>
        <div style={headerStyle} onClick={inline ? undefined : loadExplanation}>
          <Sparkles size={15} color="#818cf8" />
          <span style={{ fontWeight: 700, fontSize: '0.82rem', flex: 1 }}>AI Security Explanation</span>
          <button
            onClick={loadExplanation}
            style={{
              display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.75rem',
              fontWeight: 600, padding: '5px 12px', borderRadius: '6px', cursor: 'pointer',
              background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.4)',
              color: '#818cf8',
            }}
          >
            <Sparkles size={12} /> Generate Explanation
          </button>
        </div>
        <div style={{ padding: '14px 16px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Click to generate a developer-friendly AI explanation backed by verified security data.
          {!llmAvailable && llmAvailable !== null && (
            <span style={{ marginLeft: 6, color: '#eab308' }}>⚠ Gemini API key not configured — will use deterministic explanation.</span>
          )}
        </div>
      </div>
    );
  }

  if (state === 'loading') {
    return (
      <div style={cardStyle}>
        <div style={headerStyle}>
          <Loader2 size={15} color="#818cf8" style={{ animation: 'spin 1s linear infinite' }} />
          <span style={{ fontWeight: 700, fontSize: '0.82rem', color: '#818cf8' }}>
            Generating AI Explanation…
          </span>
        </div>
        <div style={{ padding: '14px 16px', display: 'flex', gap: '10px', alignItems: 'center', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Sending verified facts to Gemini. This takes a few seconds.
        </div>
      </div>
    );
  }

  if (state === 'error') {
    return (
      <div style={{ ...cardStyle, borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.04)' }}>
        <div style={headerStyle}>
          <AlertCircle size={15} color="#ef4444" />
          <span style={{ fontWeight: 700, fontSize: '0.82rem', color: '#ef4444', flex: 1 }}>Explanation unavailable</span>
          <button
            onClick={() => setState('idle')}
            style={{ fontSize: '0.72rem', color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
          >
            Retry
          </button>
        </div>
        <div style={{ padding: '12px 16px', fontSize: '0.77rem', color: '#fca5a5' }}>{error}</div>
      </div>
    );
  }

  // ── Done — show full explanation ──
  const exp = explanation || {};
  const isAI = exp.generated_by === 'GEMINI';

  return (
    <div style={cardStyle}>
      {/* Header */}
      <div
        style={headerStyle}
        onClick={inline ? () => setExpanded(p => !p) : undefined}
      >
        <Sparkles size={15} color="#818cf8" />
        <span style={{ fontWeight: 700, fontSize: '0.82rem', flex: 1 }}>AI Security Explanation</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <GeneratedByBadge generatedBy={exp.generated_by} />
          <ConfidencePill confidence={exp.confidence} />
          {inline && (
            expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />
          )}
        </div>
      </div>

      {/* Summary — always visible when done */}
      <div style={{ padding: '14px 16px', borderBottom: expanded ? '1px solid rgba(99,102,241,0.12)' : 'none' }}>
        <p style={{ fontSize: '0.84rem', lineHeight: 1.65, margin: 0 }}>{exp.summary}</p>

        {isAI && (
          <p style={{ fontSize: '0.67rem', color: 'var(--text-muted)', marginTop: '8px' }}>
            ⚠ AI-generated guidance. Security facts (CVE, CVSS, versions) are from verified OSV/security data and were not modified by the AI.
          </p>
        )}
      </div>

      {/* Full detail — collapsible on inline mode */}
      {expanded && (
        <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>

          {exp.why_it_matters && (
            <Section title="WHY THIS MATTERS" accent="#f97316">
              {exp.why_it_matters}
            </Section>
          )}

          {exp.technical_explanation && (
            <Section title="TECHNICAL EXPLANATION" accent="#6366f1">
              {exp.technical_explanation}
            </Section>
          )}

          {exp.recommended_action && (
            <Section title="RECOMMENDED ACTION" accent="#22c55e">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <p style={{ margin: 0 }}>{exp.recommended_action}</p>
                {exp.upgrade_target && (
                  <div style={{
                    display: 'inline-flex', alignItems: 'center', gap: '6px',
                    fontFamily: 'var(--font-mono)', fontSize: '0.78rem',
                    background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.3)',
                    padding: '4px 10px', borderRadius: '6px', color: '#22c55e',
                    alignSelf: 'flex-start'
                  }}>
                    <CheckCircle2 size={12} />
                    Upgrade target: {exp.upgrade_target}
                  </div>
                )}
              </div>
            </Section>
          )}

          {(exp.verification_steps || []).length > 0 && (
            <Section title="VERIFICATION STEPS" accent="#64748b">
              <ol style={{ margin: 0, paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '5px' }}>
                {exp.verification_steps.map((step, i) => (
                  <li key={i} style={{ fontSize: '0.8rem' }}>{step}</li>
                ))}
              </ol>
            </Section>
          )}
        </div>
      )}

      {/* Toggle for inline mode when done */}
      {inline && state === 'done' && (
        <button
          onClick={() => setExpanded(p => !p)}
          style={{
            width: '100%', padding: '8px', fontSize: '0.72rem', fontWeight: 600,
            color: 'var(--text-muted)', background: 'rgba(0,0,0,0.02)',
            borderTop: '1px solid rgba(99,102,241,0.12)', border: 'none',
            cursor: 'pointer', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '4px'
          }}
        >
          {expanded ? <><ChevronDown size={12} /> Collapse</> : <><ChevronRight size={12} /> Show full explanation</>}
        </button>
      )}
    </div>
  );
}
