import React, { useState, useMemo } from 'react';
import { ArrowLeft, Shield, Package, Code, FileCode, MessageSquare, CheckCircle2 } from 'lucide-react';
import './RemediationWorkspace.css';

// ── Static Demo Data ────────────────────────────────────────────────────────
const DEMO_TICKET = {
  ticket_id: "SEC-7A3F1B",
  severity: "CRITICAL",
  risk_score: 92,
  status: "IN_PROGRESS",
  packages: [
    {
      id: "pkg-lodash",
      name: "lodash",
      version: "4.17.20",
      ecosystem: "npm",
      severity: "CRITICAL",
      cve: "CVE-2021-23337",
      cvss: 9.8,
      description: "Prototype Pollution in lodash",
      fix_version: "4.17.21",
      methods: [
        {
          id: "m-merge",
          name: "_.merge()",
          risk: "HIGH",
          occurrences: [
            { id: "occ-1", file: "src/utils/deepMerge.js", line: 23, code: "const result = _.merge(userInput, defaults);" },
            { id: "occ-2", file: "src/api/configHandler.js", line: 87, code: "_.merge(serverConfig, req.body.settings);" },
            { id: "occ-3", file: "src/middleware/auth.js", line: 41, code: "const opts = _.merge({}, defaultOpts, userOpts);" }
          ],
          explanation: "_.merge() recursively merges source objects into a target without sanitizing special keys like '__proto__', 'constructor', or 'prototype'. When user-controlled input (like req.body) is passed as a source, an attacker can inject { \"__proto__\": { \"isAdmin\": true } } to pollute Object.prototype, granting escalated privileges to every object in the application."
        },
        {
          id: "m-set",
          name: "_.set()",
          risk: "HIGH",
          occurrences: [
            { id: "occ-4", file: "src/services/userService.js", line: 112, code: "_.set(profile, path, value);" },
            { id: "occ-5", file: "src/controllers/settings.js", line: 56, code: "_.set(config, req.params.key, req.body.val);" }
          ],
          explanation: "_.set() writes a value at a dot-separated path (e.g., 'a.b.c'). If the path comes from user input, an attacker can supply '__proto__.polluted' as the path, writing arbitrary properties to Object.prototype. This affects all objects in the runtime."
        },
        {
          id: "m-setwith",
          name: "_.setWith()",
          risk: "MEDIUM",
          occurrences: [
            { id: "occ-6", file: "src/utils/transform.js", line: 34, code: "_.setWith(obj, path, val, Object);" }
          ],
          explanation: "Similar vector to _.set() but with a customizer function. The path-based access still permits prototype pollution when unsanitized user input controls the path argument. Lower risk because the customizer can act as a partial guard."
        }
      ]
    },
    {
      id: "pkg-express",
      name: "express",
      version: "4.17.1",
      ecosystem: "npm",
      severity: "HIGH",
      cve: "CVE-2024-29041",
      cvss: 7.5,
      description: "Open Redirect vulnerability in express",
      fix_version: "4.19.2",
      methods: [
        {
          id: "m-static",
          name: "express.static()",
          risk: "HIGH",
          occurrences: [
            { id: "occ-7", file: "src/server.js", line: 15, code: "app.use('/public', express.static('uploads'));" },
            { id: "occ-8", file: "src/app.js", line: 8, code: "app.use(express.static(path.join(__dirname, 'dist')));" }
          ],
          explanation: "express.static() serves files from a directory. In versions before 4.19.2, specially crafted URLs with encoded path separators (%2e, %2f) can traverse outside the root directory, letting attackers read sensitive files like .env, package.json, or /etc/passwd on the server."
        },
        {
          id: "m-redirect",
          name: "res.redirect()",
          risk: "MEDIUM",
          occurrences: [
            { id: "occ-9", file: "src/api/auth.js", line: 67, code: "res.redirect(req.query.returnUrl);" },
            { id: "occ-10", file: "src/routes/oauth.js", line: 23, code: "res.redirect(callbackUrl);" }
          ],
          explanation: "res.redirect() does not validate the destination URL in older Express versions. If the redirect target comes from user input (like req.query.returnUrl), an attacker can craft a link that redirects users to a phishing site, making the attack appear legitimate because it originates from your domain."
        }
      ]
    }
  ]
};


// ── Layout Constants ────────────────────────────────────────────────────────
const COL = {
  ROOT: 60,
  PACKAGE: 300,
  METHOD: 560,
  OCCURRENCE: 790,
  EXPLANATION: 1100,
};

const NODE_HEIGHT = {
  ROOT: 120,
  PACKAGE: 110,
  METHOD: 80,
  OCCURRENCE: 70,
  EXPLANATION: 0, // dynamic
};

const ROW_GAP = 20;


// ── Edge Component ──────────────────────────────────────────────────────────
function DagEdge({ x1, y1, x2, y2, severity = 'default', stagger = 0 }) {
  const midX = (x1 + x2) / 2;
  const d = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;

  return (
    <path
      className={`dag-edge dag-edge-${severity} stagger-${stagger}`}
      d={d}
    />
  );
}


// ── Severity Badge ──────────────────────────────────────────────────────────
function SeverityBadge({ severity }) {
  const cls = `badge badge-${severity === 'CRITICAL' ? 'critical' : severity === 'HIGH' ? 'high' : severity === 'MEDIUM' ? 'medium' : 'low'}`;
  return <span className={cls} style={{ fontSize: '0.65rem', padding: '2px 6px' }}>{severity}</span>;
}


// ── Main Component ──────────────────────────────────────────────────────────
export default function RemediationWorkspace({ ticket, onBack, onResolve }) {
  const data = DEMO_TICKET; // Static demo — swap for real data later

  const [expandedPackages, setExpandedPackages] = useState(new Set());
  const [expandedMethods, setExpandedMethods] = useState(new Set());
  const [selectedOccurrence, setSelectedOccurrence] = useState(null);

  // Toggle package expansion
  const togglePackage = (pkgId) => {
    setExpandedPackages(prev => {
      const next = new Set(prev);
      if (next.has(pkgId)) {
        next.delete(pkgId);
        // Collapse all children
        data.packages.find(p => p.id === pkgId)?.methods.forEach(m => {
          setExpandedMethods(mp => { const n = new Set(mp); n.delete(m.id); return n; });
        });
        setSelectedOccurrence(null);
      } else {
        next.add(pkgId);
      }
      return next;
    });
  };

  // Toggle method expansion
  const toggleMethod = (methodId) => {
    setExpandedMethods(prev => {
      const next = new Set(prev);
      if (next.has(methodId)) {
        next.delete(methodId);
        setSelectedOccurrence(null);
      } else {
        next.add(methodId);
      }
      return next;
    });
  };

  // Select occurrence → show explanation
  const selectOccurrence = (occId, methodId) => {
    if (selectedOccurrence?.occId === occId) {
      setSelectedOccurrence(null);
    } else {
      setSelectedOccurrence({ occId, methodId });
    }
  };


  // ── Layout Calculation ──────────────────────────────────────────────────
  const layout = useMemo(() => {
    const nodes = [];
    const edges = [];

    // Root node
    let totalVisibleChildren = 0;
    data.packages.forEach(pkg => {
      totalVisibleChildren++;
      if (expandedPackages.has(pkg.id)) {
        pkg.methods.forEach(m => {
          totalVisibleChildren++;
          if (expandedMethods.has(m.id)) {
            totalVisibleChildren += m.occurrences.length;
            if (selectedOccurrence && m.occurrences.some(o => o.id === selectedOccurrence.occId)) {
              totalVisibleChildren++;
            }
          }
        });
      }
    });

    const totalHeight = Math.max(500, totalVisibleChildren * 100);
    const rootY = totalHeight / 2 - NODE_HEIGHT.ROOT / 2;

    nodes.push({
      type: 'root',
      id: 'root',
      x: COL.ROOT,
      y: rootY,
      data: { ticket_id: data.ticket_id, severity: data.severity, risk_score: data.risk_score },
    });

    // Package nodes
    const pkgCount = data.packages.length;
    const pkgTotalHeight = pkgCount * NODE_HEIGHT.PACKAGE + (pkgCount - 1) * ROW_GAP;
    let pkgStartY = rootY + NODE_HEIGHT.ROOT / 2 - pkgTotalHeight / 2;

    data.packages.forEach((pkg, pi) => {
      const pkgY = pkgStartY + pi * (NODE_HEIGHT.PACKAGE + ROW_GAP);

      nodes.push({
        type: 'package',
        id: pkg.id,
        x: COL.PACKAGE,
        y: pkgY,
        stagger: pi,
        data: pkg,
        expanded: expandedPackages.has(pkg.id),
      });

      edges.push({
        x1: COL.ROOT + 180,
        y1: rootY + NODE_HEIGHT.ROOT / 2,
        x2: COL.PACKAGE,
        y2: pkgY + NODE_HEIGHT.PACKAGE / 2,
        severity: pkg.severity.toLowerCase(),
        stagger: pi,
      });

      // Method nodes (if package expanded)
      if (expandedPackages.has(pkg.id)) {
        const methodCount = pkg.methods.length;
        const methodTotalHeight = methodCount * NODE_HEIGHT.METHOD + (methodCount - 1) * ROW_GAP;
        let methodStartY = pkgY + NODE_HEIGHT.PACKAGE / 2 - methodTotalHeight / 2;

        pkg.methods.forEach((method, mi) => {
          const methodY = methodStartY + mi * (NODE_HEIGHT.METHOD + ROW_GAP);

          nodes.push({
            type: 'method',
            id: method.id,
            x: COL.METHOD,
            y: methodY,
            stagger: mi,
            data: method,
            expanded: expandedMethods.has(method.id),
          });

          edges.push({
            x1: COL.PACKAGE + 210,
            y1: pkgY + NODE_HEIGHT.PACKAGE / 2,
            x2: COL.METHOD,
            y2: methodY + NODE_HEIGHT.METHOD / 2,
            severity: method.risk.toLowerCase(),
            stagger: mi + pkgCount,
          });

          // Occurrence nodes (if method expanded)
          if (expandedMethods.has(method.id)) {
            const occCount = method.occurrences.length;
            const occTotalHeight = occCount * NODE_HEIGHT.OCCURRENCE + (occCount - 1) * (ROW_GAP / 2);
            let occStartY = methodY + NODE_HEIGHT.METHOD / 2 - occTotalHeight / 2;

            method.occurrences.forEach((occ, oi) => {
              const occY = occStartY + oi * (NODE_HEIGHT.OCCURRENCE + ROW_GAP / 2);

              nodes.push({
                type: 'occurrence',
                id: occ.id,
                x: COL.OCCURRENCE,
                y: occY,
                stagger: oi,
                data: occ,
                methodId: method.id,
                selected: selectedOccurrence?.occId === occ.id,
              });

              edges.push({
                x1: COL.METHOD + 180,
                y1: methodY + NODE_HEIGHT.METHOD / 2,
                x2: COL.OCCURRENCE,
                y2: occY + NODE_HEIGHT.OCCURRENCE / 2,
                severity: 'default',
                stagger: oi + pkgCount + methodCount,
              });

              // Explanation card (if occurrence selected)
              if (selectedOccurrence?.occId === occ.id) {
                nodes.push({
                  type: 'explanation',
                  id: `explain-${occ.id}`,
                  x: COL.EXPLANATION,
                  y: occY - 40,
                  stagger: 0,
                  data: {
                    explanation: method.explanation,
                    fix_version: data.packages.find(p => p.methods.some(m => m.id === method.id))?.fix_version,
                    pkg_name: data.packages.find(p => p.methods.some(m => m.id === method.id))?.name,
                  },
                });

                edges.push({
                  x1: COL.OCCURRENCE + 260,
                  y1: occY + NODE_HEIGHT.OCCURRENCE / 2,
                  x2: COL.EXPLANATION,
                  y2: occY,
                  severity: 'default',
                  stagger: 0,
                });
              }
            });
          }
        });
      }
    });

    // Calculate canvas dimensions
    let maxX = COL.EXPLANATION + 360;
    let maxY = 0;
    nodes.forEach(n => {
      const nodeBottom = n.y + (n.type === 'explanation' ? 250 : NODE_HEIGHT[n.type.toUpperCase()] || 100);
      if (nodeBottom > maxY) maxY = nodeBottom;
    });

    return { nodes, edges, width: maxX, height: Math.max(maxY + 60, 550) };
  }, [data, expandedPackages, expandedMethods, selectedOccurrence]);


  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="remediation-workspace">
      {/* Header */}
      <div className="remediation-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button className="remediation-back-btn" onClick={onBack}>
            <ArrowLeft size={16} /> Back to Tickets
          </button>
          <div className="remediation-title">
            <Shield size={22} color="var(--primary)" />
            <h3>Remediation Workspace</h3>
            <SeverityBadge severity={data.severity} />
          </div>
        </div>
        <button className="resolve-btn" onClick={() => onResolve && onResolve(data.ticket_id)}>
          <CheckCircle2 size={16} /> Mark as Resolved
        </button>
      </div>

      {/* Legend */}
      <div className="dag-legend">
        <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Legend:</span>
        <div className="dag-legend-item">
          <div className="dag-legend-dot" style={{ background: 'var(--primary)' }} />
          <span>Ticket</span>
        </div>
        <div className="dag-legend-item">
          <div className="dag-legend-dot" style={{ background: 'var(--critical)' }} />
          <span>Package</span>
        </div>
        <div className="dag-legend-item">
          <div className="dag-legend-dot" style={{ background: 'var(--high)' }} />
          <span>Method</span>
        </div>
        <div className="dag-legend-item">
          <div className="dag-legend-dot" style={{ background: 'var(--info)' }} />
          <span>Occurrence</span>
        </div>
        <div className="dag-legend-item">
          <div className="dag-legend-dot" style={{ background: 'var(--primary)', opacity: 0.5 }} />
          <span>Explanation</span>
        </div>
        <span style={{ marginLeft: 'auto', fontStyle: 'italic' }}>Click nodes to expand →</span>
      </div>

      {/* DAG Canvas */}
      <div className="dag-canvas">
        <div className="dag-nodes-container" style={{ width: layout.width, height: layout.height }}>

          {/* SVG Edges */}
          <svg className="dag-edges" style={{ width: layout.width, height: layout.height }}>
            <defs>
              <linearGradient id="edge-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="rgba(99,102,241,0.5)" />
                <stop offset="100%" stopColor="rgba(139,92,246,0.3)" />
              </linearGradient>
            </defs>
            {layout.edges.map((edge, i) => (
              <DagEdge key={i} {...edge} />
            ))}
          </svg>

          {/* Nodes */}
          {layout.nodes.map((node) => {
            if (node.type === 'root') {
              return (
                <div
                  key={node.id}
                  className="dag-node dag-root"
                  style={{ left: node.x, top: node.y }}
                >
                  <div className="root-icon">🎫</div>
                  <div className="root-ticket-id">{node.data.ticket_id}</div>
                  <div className="root-label">Risk Score: {node.data.risk_score}/100</div>
                </div>
              );
            }

            if (node.type === 'package') {
              return (
                <div
                  key={node.id}
                  className={`dag-node dag-package severity-${node.data.severity.toLowerCase()} stagger-${node.stagger} ${node.expanded ? 'expanded' : ''}`}
                  style={{ left: node.x, top: node.y }}
                  onClick={() => togglePackage(node.id)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                    <Package size={14} color="var(--text-muted)" />
                    <span className="pkg-name">{node.data.name}</span>
                  </div>
                  <div className="pkg-version">v{node.data.version}</div>
                  <div className="pkg-cve">{node.data.cve} • CVSS {node.data.cvss}</div>
                  <div className="pkg-footer">
                    <SeverityBadge severity={node.data.severity} />
                    <span className="pkg-expand-hint">
                      {node.expanded ? '▾ collapse' : '▸ show methods'}
                    </span>
                  </div>
                </div>
              );
            }

            if (node.type === 'method') {
              return (
                <div
                  key={node.id}
                  className={`dag-node dag-method stagger-${node.stagger} ${node.expanded ? 'expanded' : ''}`}
                  style={{ left: node.x, top: node.y }}
                  onClick={() => toggleMethod(node.id)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                    <Code size={13} color="var(--high)" />
                    <span className="method-name">{node.data.name}</span>
                  </div>
                  <div className="method-risk">
                    <SeverityBadge severity={node.data.risk} />
                  </div>
                  <div className="method-count">
                    {node.expanded ? '▾ collapse' : `▸ ${node.data.occurrences.length} occurrence${node.data.occurrences.length !== 1 ? 's' : ''}`}
                  </div>
                </div>
              );
            }

            if (node.type === 'occurrence') {
              return (
                <div
                  key={node.id}
                  className={`dag-node dag-occurrence stagger-${node.stagger} ${node.selected ? 'expanded' : ''}`}
                  style={{ left: node.x, top: node.y }}
                  onClick={() => selectOccurrence(node.data.id, node.methodId)}
                >
                  <div className="occ-file">
                    <FileCode size={12} />
                    {node.data.file}:{node.data.line}
                  </div>
                  <div className="occ-code">{node.data.code}</div>
                </div>
              );
            }

            if (node.type === 'explanation') {
              return (
                <div
                  key={node.id}
                  className="dag-node dag-explanation"
                  style={{ left: node.x, top: node.y }}
                >
                  <div className="explain-header">
                    <MessageSquare size={14} />
                    Why is this risky?
                  </div>
                  <div className="explain-text">{node.data.explanation}</div>
                  {node.data.fix_version && (
                    <div className="explain-fix">
                      ✅ Fix: Upgrade {node.data.pkg_name} to v{node.data.fix_version}
                    </div>
                  )}
                </div>
              );
            }

            return null;
          })}
        </div>
      </div>
    </div>
  );
}
