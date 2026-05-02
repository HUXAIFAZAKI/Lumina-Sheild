import networkx as nx
from pyvis.network import Network
from utils.api_clients import dns_resolve_all, whois_lookup, crt_sh_subdomains
import streamlit as st
import os
import tempfile
import socket

def build_genealogy_graph(domain: str) -> tuple:
    G = nx.DiGraph()
    G.add_node(domain, label=domain, color="#1f78b4", title="Target Domain", type="domain",
               size=30, font={"size": 16, "bold": True})

    # ---- DNS Resolution via dnspython (free, always works) ----
    dns_records = dns_resolve_all(domain)
    ips = set()

    # A records â†’ IP nodes
    for ip in dns_records.get("A", []):
        ips.add(ip)
        G.add_node(ip, label=ip, color="#33a02c", title=f"IP Address (A record)", type="ip", size=20)
        G.add_edge(domain, ip, title="A record", color="#33a02c", width=2)

    # AAAA records
    for ip in dns_records.get("AAAA", []):
        ips.add(ip)
        G.add_node(ip, label=ip, color="#2ca089", title="IPv6 Address (AAAA record)", type="ip", size=18)
        G.add_edge(domain, ip, title="AAAA record", color="#2ca089")

    # MX records â†’ mail server nodes
    for mx in dns_records.get("MX", []):
        mx_host = mx.split()[-1].rstrip(".") if " " in mx else mx.rstrip(".")
        G.add_node(mx_host, label=mx_host, color="#ff7f00", title=f"Mail Server (MX): {mx}", type="mx", size=18)
        G.add_edge(domain, mx_host, title=f"MX: {mx}", color="#ff7f00")

    # NS records â†’ nameserver nodes
    for ns in dns_records.get("NS", []):
        ns_host = ns.rstrip(".")
        G.add_node(ns_host, label=ns_host, color="#6a3d9a", title="Nameserver (NS)", type="ns", size=16)
        G.add_edge(domain, ns_host, title="NS record", color="#6a3d9a")

    # TXT records (show as tooltip on domain node, but also add notable ones)
    txt_records = dns_records.get("TXT", [])
    if txt_records:
        # Update domain node title with TXT info
        txt_summary = "\n".join([f"TXT: {t[:80]}" for t in txt_records[:5]])
        G.nodes[domain]["title"] = f"Target Domain\n{txt_summary}"

        # Check for SPF, DMARC, etc.
        for txt in txt_records:
            if "v=spf1" in txt.lower():
                G.add_node("SPF Record", label="SPF âœ“", color="#b2df8a",
                          title=f"SPF: {txt[:120]}", type="txt", size=12)
                G.add_edge(domain, "SPF Record", title="SPF", color="#b2df8a")
            elif "v=dmarc" in txt.lower():
                G.add_node("DMARC Record", label="DMARC âœ“", color="#b2df8a",
                          title=f"DMARC: {txt[:120]}", type="txt", size=12)
                G.add_edge(domain, "DMARC Record", title="DMARC", color="#b2df8a")

    # Fallback: direct IP resolution if dns_resolve_all returned nothing
    if not ips:
        try:
            direct_ip = socket.gethostbyname(domain)
            ips.add(direct_ip)
            G.add_node(direct_ip, label=direct_ip, color="#33a02c", title="Resolved IP (fallback)", type="ip", size=20)
            G.add_edge(domain, direct_ip, title="resolves to", color="#33a02c", width=2)
        except:
            pass

    # ---- Subdomains from crt.sh ----
    subs = crt_sh_subdomains(domain)
    sibling_count = 0
    if subs:
        for sub in subs:
            if sub != domain and sibling_count < 15:  # Cap to avoid graph overload
                sibling_count += 1
                G.add_node(sub, label=sub, color="#fb9a99", title="Subdomain (crt.sh)", type="domain", size=14)
                G.add_edge(domain, sub, title="subdomain", color="#fb9a99")

    # ---- WHOIS ----
    w = whois_lookup(domain)
    registrar = w.get("registrar")
    if registrar:
        if isinstance(registrar, list):
            registrar = registrar[0]
        G.add_node(registrar, label=registrar, color="#e31a1c", title="Registrar", type="registrar", size=18)
        G.add_edge(domain, registrar, title="registered with", color="#e31a1c")

    country = w.get("country")
    if country:
        G.add_node(f"Country: {country}", label=f"ðŸŒ {country}", color="#cab2d6",
                  title=f"Registration Country: {country}", type="country", size=14)
        G.add_edge(domain, f"Country: {country}", title="registered in", color="#cab2d6")

    # ---- Build PyVis Network ----
    net = Network(height="550px", width="100%", directed=True, bgcolor="#ffffff", font_color="#333333")
    net.from_nx(G)

    # Better physics settings for cleaner layout
    net.set_options("""
    {
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -50,
                "centralGravity": 0.01,
                "springLength": 150,
                "springConstant": 0.08,
                "damping": 0.4
            },
            "solver": "forceAtlas2Based",
            "stabilization": {"iterations": 100}
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 200,
            "navigationButtons": true,
            "keyboard": true
        },
        "edges": {
            "smooth": {"type": "curvedCW", "roundness": 0.2},
            "arrows": {"to": {"enabled": true, "scaleFactor": 0.6}}
        },
        "nodes": {
            "borderWidth": 2,
            "borderWidthSelected": 4,
            "shadow": true
        }
    }
    """)

    # Save to temp HTML
    fd, path = tempfile.mkstemp(suffix=".html", prefix="graph_")
    os.close(fd)
    net.save_graph(path)
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    os.remove(path)
    
    # Generate GEXF
    try:
        gexf = "\n".join(nx.generate_gexf(G))
    except Exception:
        gexf = "<gexf></gexf>"

    return html, gexf

def campaign_similarity(iocs: dict) -> list:
    """Compare with previous submissions to find campaign overlaps."""
    try:
        from data.db import get_db
        conn = get_db()
        matches = []
        
        my_ips = iocs.get("ips", [])
        my_domains = iocs.get("domains", [])
        
        for ip in my_ips:
            rows = conn.execute("SELECT submission_id FROM iocs WHERE type='IP' AND value=?", (ip,)).fetchall()
            for r in rows:
                matches.append({"type": "Shared IP", "value": ip, "submission_id": r["submission_id"]})
                
        for d in my_domains:
            rows = conn.execute("SELECT submission_id FROM iocs WHERE type='Domain' AND value=?", (d,)).fetchall()
            for r in rows:
                matches.append({"type": "Shared Domain", "value": d, "submission_id": r["submission_id"]})
                
        conn.close()
        return matches
    except:
        return []

def generate_typosquatting(domain: str) -> list:
    """Generate and test basic domain typosquatting permutations."""
    parts = domain.split(".")
    if len(parts) < 2: return []
    base = parts[0]
    tld = ".".join(parts[1:])
    
    permutations = set()
    # Omission
    for i in range(len(base)):
        permutations.add(base[:i] + base[i+1:] + "." + tld)
    # Repetition
    for i in range(len(base)):
        permutations.add(base[:i] + base[i]*2 + base[i+1:] + "." + tld)
    # Common tricks
    permutations.add(base + "-" + tld.replace(".", "-") + ".com")
    permutations.add(base + "s." + tld)
    
    import socket
    active = []
    # Test up to 15 permutations to avoid UI freeze
    for p in list(permutations)[:15]:
        if p == domain or len(p) < 4: continue
        try:
            ip = socket.gethostbyname(p)
            active.append({"domain": p, "ip": ip})
        except:
            pass
    return active