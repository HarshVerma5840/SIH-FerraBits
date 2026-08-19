def _create_nodes(components):
    nodes = []
    purl_to_node = {}
    for c in components:
        purl = c["purl"]
        
        # Calculate mock/real risk and vuln count from component
        vuln_count = len(c.get("vulnerabilities", []))
        risk_score = c.get("risk_score", 0)
        
        node = {
            "id": purl,
            "label": f"{c['name']} ({c.get('version', 'unknown')})",
            "name": c["name"],
            "version": c.get("version"),
            "ecosystem": c["ecosystem"],
            "type": c.get("type", "library"),
            "risk_score": risk_score,
            "vulnerability_count": vuln_count,
            "license": c.get("license", "Unknown"),
            "direct": c.get("direct", True),
            "ai_score": c.get("anomaly_score", 0)
        }
        nodes.append(node)
        purl_to_node[purl] = node
    return nodes, purl_to_node

def _create_edges(components, dependencies_relations):
    edges = []
    # If we have direct relationships parsed from lockfiles
    if dependencies_relations:
        for parent, children in dependencies_relations.items():
            parent_id = "root" if parent == "root" else parent
            for child in children:
                edges.append({
                    "source": parent_id,
                    "target": child
                })
    else:
        # Fallback to direct vs transitive heuristics
        for c in components:
            purl = c["purl"]
            if c.get("direct", True):
                edges.append({
                    "source": "root",
                    "target": purl
                })
    return edges

def build_dependency_graph(components, dependencies_relations=None):
    """
    Engine 30: Dependency Attack Graph Engine
    Builds nodes and edges representing the dependency tree.
    Nodes carry version, risk, vulnerabilities, and license details.
    """
    nodes = []
    
    # 1. Add application root node
    nodes.append({
        "id": "root",
        "label": "Application",
        "type": "root",
        "risk_score": 0,
        "vulnerability_count": 0
    })
    
    # Track nodes by PURL
    component_nodes, _ = _create_nodes(components)
    nodes.extend(component_nodes)
        
    # 2. Add edges
    edges = _create_edges(components, dependencies_relations)
            
    # Calculate root metrics
    total_vulns = sum(n["vulnerability_count"] for n in nodes if n["id"] != "root")
    max_risk = max([n["risk_score"] for n in nodes if n["id"] != "root"] or [0])
    
    for n in nodes:
        if n["id"] == "root":
            n["vulnerability_count"] = total_vulns
            n["risk_score"] = max_risk
            
    return {
        "nodes": nodes,
        "edges": edges
    }

def calculate_blast_radius(component_purl, nodes, edges):
    """
    Engine 31: Blast Radius Analysis Engine
    Finds all downstream nodes (dependents) impacted by a vulnerable dependency.
    Traces paths back to the application root.
    """
    _ = nodes
    # Build reverse adjacency list (child -> list of parents)
    rev_adj = {}
    for edge in edges:
        s = edge["source"]
        t = edge["target"]
        if t not in rev_adj:
            rev_adj[t] = []
        if s not in rev_adj[t]:
            rev_adj[t].append(s)
            
    affected_nodes = set()
    paths = []
    
    def dfs_trace(current_node, current_path):
        affected_nodes.add(current_node)
        
        # If we reached root, save path
        if current_node == "root":
            paths.append(list(reversed(current_path)))
            return
            
        parents = rev_adj.get(current_node, [])
        if not parents:
            # Reached a dead end without root, but still record path
            paths.append(list(reversed(current_path)))
            return
            
        for p in parents:
            dfs_trace(p, current_path + [p])
            
    dfs_trace(component_purl, [component_purl])
    
    # Remove original node and root from count of affected intermediate libraries
    clean_affected = {n for n in affected_nodes if n not in [component_purl, "root"]}
    
    return {
        "component_purl": component_purl,
        "impact_score": len(clean_affected) + (1 if "root" in affected_nodes else 0),
        "affected_dependents_count": len(clean_affected),
        "affected_dependents": list(clean_affected),
        "paths": paths,
        "production_exposure": "root" in affected_nodes
    }
