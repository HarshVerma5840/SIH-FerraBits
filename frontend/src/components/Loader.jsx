import React from 'react';

// ── Spinning circle loader ────────────────────────────────────────────────────
export function Spinner({ size = 20, color = 'var(--primary)' }) {
  return (
    <svg
      width={size} height={size}
      viewBox="0 0 24 24"
      style={{ animation: 'spin 0.8s linear infinite', flexShrink: 0 }}
    >
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <circle cx="12" cy="12" r="10" fill="none" stroke={color} strokeWidth="3" strokeDasharray="31.4" strokeDashoffset="10" strokeLinecap="round" />
    </svg>
  );
}

// ── Full-page loading overlay ─────────────────────────────────────────────────
export function PageLoader({ label = 'Loading…' }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', gap: '16px', padding: '80px 0',
    }}>
      <Spinner size={40} />
      <span style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>{label}</span>
    </div>
  );
}

// ── Skeleton shimmer pulse ────────────────────────────────────────────────────
const shimmerStyle = {
  background: 'linear-gradient(90deg, rgba(0,0,0,0.04) 25%, rgba(0,0,0,0.08) 50%, rgba(0,0,0,0.04) 75%)',
  backgroundSize: '200% 100%',
  animation: 'shimmer 1.6s infinite',
  borderRadius: '6px',
};

export function SkeletonBlock({ width = '100%', height = '16px', style = {} }) {
  return (
    <>
      <style>{`@keyframes shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }`}</style>
      <div style={{ ...shimmerStyle, width, height, ...style }} />
    </>
  );
}

// ── Skeleton project card ─────────────────────────────────────────────────────
export function SkeletonCard() {
  return (
    <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <SkeletonBlock height="20px" width="60%" />
      <SkeletonBlock height="14px" width="90%" />
      <SkeletonBlock height="14px" width="75%" />
      <div style={{ display: 'flex', justifyContent: 'space-between', paddingTop: '8px' }}>
        <SkeletonBlock height="28px" width="30%" />
        <SkeletonBlock height="28px" width="25%" />
      </div>
    </div>
  );
}

// ── Skeleton table rows ───────────────────────────────────────────────────────
export function SkeletonTableRows({ cols = 5, rows = 4 }) {
  return Array.from({ length: rows }).map((_, r) => (
    <tr key={r} style={{ borderBottom: '1px solid var(--border-color)' }}>
      {Array.from({ length: cols }).map((_, c) => (
        <td key={c} style={{ padding: '16px' }}>
          <SkeletonBlock height="14px" width={c === 0 ? '70%' : '50%'} />
        </td>
      ))}
    </tr>
  ));
}
