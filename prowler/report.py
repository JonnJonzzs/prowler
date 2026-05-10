import json
import os
from datetime import datetime
from typing import Any


def save_json(results: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(results, f, indent=2)


def _esc(text: Any) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def save_html(results: dict, domain: str, path: str) -> None:
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    subdomains = results.get("subdomains", {}).get("subdomains", [])
    alive = results.get("probe", {}).get("alive", [])
    hosts = results.get("portscan", {}).get("hosts", [])
    endpoints = results.get("dirscan", {}).get("endpoints", [])

    def section(title: str, icon: str, content_html: str, count: int) -> str:
        return f"""
        <div class="section">
            <button class="collapsible" onclick="toggle(this)">
                <span class="icon">{icon}</span>
                <span class="title">{_esc(title)}</span>
                <span class="badge">{count}</span>
                <span class="chevron">&#9660;</span>
            </button>
            <div class="content">
                {content_html}
            </div>
        </div>
        """

    def table(headers: list[str], rows: list[list[Any]]) -> str:
        if not rows:
            return '<p class="empty">No results.</p>'
        header_html = "".join(f"<th>{_esc(h)}</th>" for h in headers)
        rows_html = ""
        for row in rows:
            cells = "".join(f"<td>{_esc(c)}</td>" for c in row)
            rows_html += f"<tr>{cells}</tr>"
        return f"""
        <table>
            <thead><tr>{header_html}</tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
        """

    # Build section content blocks
    subdomain_table = table(["Subdomain"], [[s] for s in subdomains])

    alive_table = table(
        ["URL", "Status", "Title", "Content-Length"],
        [[e.get("url"), e.get("status"), e.get("title", ""), e.get("length", "")] for e in alive],
    )

    port_rows = []
    for h in hosts:
        for p in h.get("ports", []):
            port_rows.append([h["host"], p["port"], p.get("protocol", "tcp"), p.get("service", "")])
    ports_table = table(["Host", "Port", "Protocol", "Service"], port_rows)

    endpoint_table = table(
        ["URL", "Status", "Size (bytes)"],
        [[e.get("url"), e.get("status"), e.get("size", "")] for e in endpoints],
    )

    sections_html = (
        section("Subdomains", "&#127760;", subdomain_table, len(subdomains))
        + section("Alive HTTP Services", "&#128308;", alive_table, len(alive))
        + section("Open Ports", "&#128268;", ports_table, len(port_rows))
        + section("Discovered Endpoints", "&#128193;", endpoint_table, len(endpoints))
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>reconx report — {_esc(domain)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Segoe UI', system-ui, sans-serif;
    line-height: 1.6;
    padding: 2rem;
  }}
  a {{ color: #58a6ff; }}
  .banner {{
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.5rem 2rem;
    margin-bottom: 2rem;
    background: #161b22;
  }}
  .banner h1 {{
    font-size: 2rem;
    color: #58a6ff;
    letter-spacing: 0.05em;
    font-family: monospace;
  }}
  .banner .sub {{
    color: #8b949e;
    font-size: 0.9rem;
    margin-top: 0.4rem;
  }}
  .disclaimer {{
    background: #1c2128;
    border-left: 4px solid #f85149;
    padding: 0.75rem 1rem;
    border-radius: 4px;
    margin-top: 1rem;
    font-size: 0.85rem;
    color: #f85149;
  }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.2rem;
    text-align: center;
  }}
  .card .count {{
    font-size: 2.5rem;
    font-weight: bold;
    color: #58a6ff;
  }}
  .card .label {{
    font-size: 0.8rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 0.3rem;
  }}
  .section {{
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-bottom: 1.2rem;
    overflow: hidden;
  }}
  .collapsible {{
    width: 100%;
    background: #161b22;
    border: none;
    color: #c9d1d9;
    padding: 1rem 1.5rem;
    text-align: left;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 1rem;
    transition: background 0.15s;
  }}
  .collapsible:hover {{ background: #1c2128; }}
  .collapsible .icon {{ font-size: 1.2rem; }}
  .collapsible .title {{ flex: 1; font-weight: 600; }}
  .collapsible .badge {{
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 999px;
    padding: 0.1rem 0.6rem;
    font-size: 0.8rem;
    color: #58a6ff;
    min-width: 2rem;
    text-align: center;
  }}
  .collapsible .chevron {{ color: #8b949e; font-size: 0.8rem; transition: transform 0.2s; }}
  .collapsible.open .chevron {{ transform: rotate(180deg); }}
  .content {{
    display: none;
    padding: 1rem 1.5rem;
    border-top: 1px solid #30363d;
    overflow-x: auto;
  }}
  .content.visible {{ display: block; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
  }}
  th {{
    background: #1c2128;
    color: #8b949e;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.06em;
    padding: 0.6rem 0.8rem;
    text-align: left;
    border-bottom: 1px solid #30363d;
  }}
  td {{
    padding: 0.55rem 0.8rem;
    border-bottom: 1px solid #21262d;
    word-break: break-all;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2128; }}
  .empty {{ color: #8b949e; font-style: italic; padding: 0.5rem 0; }}
  footer {{
    margin-top: 3rem;
    text-align: center;
    color: #484f58;
    font-size: 0.8rem;
  }}
</style>
</head>
<body>

<div class="banner">
  <h1>&#9670; reconx</h1>
  <div class="sub">Target: <strong>{_esc(domain)}</strong> &nbsp;|&nbsp; Scan date: {_esc(date_str)}</div>
  <div class="disclaimer">
    &#9888; This tool is intended for authorized bug bounty and security testing ONLY.
    Unauthorized scanning is illegal and unethical. Always obtain written permission before testing.
  </div>
</div>

<div class="summary-grid">
  <div class="card"><div class="count">{len(subdomains)}</div><div class="label">Subdomains</div></div>
  <div class="card"><div class="count">{len(alive)}</div><div class="label">Alive Services</div></div>
  <div class="card"><div class="count">{len(hosts)}</div><div class="label">Hosts Scanned</div></div>
  <div class="card"><div class="count">{len(port_rows)}</div><div class="label">Open Ports</div></div>
  <div class="card"><div class="count">{len(endpoints)}</div><div class="label">Endpoints Found</div></div>
</div>

{sections_html}

<footer>Generated by reconx &bull; {_esc(date_str)}</footer>

<script>
function toggle(btn) {{
  btn.classList.toggle('open');
  var content = btn.nextElementSibling;
  content.classList.toggle('visible');
}}
// Open first section by default
document.addEventListener('DOMContentLoaded', function() {{
  var first = document.querySelector('.collapsible');
  if (first) toggle(first);
}});
</script>
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
