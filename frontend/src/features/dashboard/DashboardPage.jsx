import React from 'react';
import { Activity, Database, Layers, AlertTriangle, ArrowRight } from 'lucide-react';
import { SkeletonCard } from '../../components/Loader';

export default function DashboardPage({ projects, tickets, isLoading, isOfflineMode, onNavigate, onSelectProject }) {
  const stats = computeStats(projects, tickets, isOfflineMode);

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>

      {/* Platform Overview KPI Card */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px', width: 'fit-content' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid rgba(0,0,0,0.05)', paddingBottom: '12px' }}>
          <div style={{ padding: '8px', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.1)', border: '1px solid rgba(99, 102, 241, 0.2)' }}>
            <Activity size={18} color="var(--primary)" />
          </div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: '500', color: 'var(--text-primary)' }}>Platform Overview</h3>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '40px' }}>
          <KpiItem icon={<Database size={14} color="var(--primary)" />} label="Scanned Projects" value={stats.totalProjects} />
          <KpiItem icon={<Layers size={14} color="var(--info)" />} label="Analyzed Dependencies" value={stats.totalDeps} />
          <KpiItem
            icon={<AlertTriangle size={14} color="var(--critical)" />}
            label="Vulnerabilities"
            value={
              <>{stats.totalCritical > 0
                ? <span style={{ color: 'var(--critical)' }}>{stats.totalCritical}</span>
                : stats.totalCritical}
                <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontWeight: '400' }}>
                  {' '}Critical / {stats.totalHigh} High
                </span></>
            }
          />
          <KpiItem icon={<Activity size={14} color="var(--low)" />} label="Avg Quality Score" value={<span style={{ color: 'var(--low)' }}>{stats.avgQuality}%</span>} />
        </div>
      </div>

      {/* Active Projects Grid */}
      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ fontSize: '1.1rem' }}>Active Projects Monitoring</h3>
          <button className="btn-primary" onClick={() => onNavigate('projects')}>
            Register & Scan <ArrowRight size={16} />
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
          {isLoading
            ? Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)
            : projects.map(p => (
              <ProjectCard
                key={p.id}
                project={p}
                onInspect={() => { onSelectProject(p.id); onNavigate('projects'); }}
              />
            ))
          }
        </div>
      </section>
    </div>
  );
}

function KpiItem({ icon, label, value }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
        {icon} {label}
      </span>
      <h3 style={{ fontSize: '1.4rem', fontWeight: '600' }}>{value}</h3>
    </div>
  );
}

function ProjectCard({ project: p, onInspect }) {
  const badgeClass = p.risk_level === 'CRITICAL' ? 'badge-critical' : (p.risk_level === 'HIGH' ? 'badge-high' : 'badge-low');
  return (
    <div className="glass-panel" style={{ padding: '20px', background: 'rgba(0,0,0,0.01)', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <h4 style={{ fontSize: '1.1rem', fontWeight: 700 }}>{p.name}</h4>
        <span className={`badge ${badgeClass}`}>{p.risk_level} RISK</span>
      </div>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', height: '40px', overflow: 'hidden' }}>{p.description}</p>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
        <div><span style={{ color: 'var(--text-muted)' }}>Vulnerabilities: </span><span style={{ fontWeight: 700, color: p.vulnerability_count > 0 ? 'var(--critical)' : 'inherit' }}>{p.vulnerability_count}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>Quality: </span><span style={{ fontWeight: 700, color: 'var(--low)' }}>{p.quality_score}%</span></div>
        <button className="btn-secondary" onClick={onInspect} style={{ padding: '4px 10px', fontSize: '0.75rem' }}>Inspect SBOM</button>
      </div>
    </div>
  );
}

function computeStats(projects, tickets, isOfflineMode) {
  if (isOfflineMode) {
    return { totalProjects: projects.length, totalDeps: 10, totalCritical: 2, totalHigh: 3, avgQuality: 89 };
  }
  return {
    totalProjects: projects.length,
    totalDeps: 0,
    totalCritical: tickets.filter(t => t.severity === 'CRITICAL' && t.status !== 'RESOLVED').length,
    totalHigh: tickets.filter(t => t.severity === 'HIGH' && t.status !== 'RESOLVED').length,
    avgQuality: projects.length ? Math.round(projects.reduce((a, p) => a + p.quality_score, 0) / projects.length) : 100,
  };
}
