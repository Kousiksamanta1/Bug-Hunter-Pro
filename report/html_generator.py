"""Generate a portable, dependency-free HTML vulnerability report."""

from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
import os
import re
from urllib.parse import urlparse

import config


SEVERITY_COLORS = {
    "CRITICAL": "#D92D20",
    "HIGH": "#E35D12",
    "MEDIUM": "#B7791F",
    "LOW": "#0077B6",
    "INFO": "#6956C7",
}
OWASP_TOP_10 = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable and Outdated Components",
    "A07:2021 Identification and Authentication Failures",
    "A08:2021 Software and Data Integrity Failures",
    "A09:2021 Security Logging and Monitoring Failures",
    "A10:2021 Server-Side Request Forgery",
]


def _safe_name(target):
    parsed = urlparse(target)
    value = parsed.netloc or parsed.path or "target"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"


def report_filename(scan, extension="html"):
    started = scan.get("started_at") or datetime.now(timezone.utc).isoformat()
    try:
        date = datetime.fromisoformat(started).strftime("%Y%m%d")
    except ValueError:
        date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return (
        f"BugHunterPro_{_safe_name(scan.get('target', 'target'))}_{date}_"
        f"{scan.get('id', '')[:8]}.{extension}"
    )


def _risk_description(score):
    score = float(score or 0)
    if score >= 8:
        return "Critical exposure requires immediate remediation."
    if score >= 6:
        return "High risk; prioritize remediation and compensating controls."
    if score >= 3:
        return "Moderate risk; address findings through the normal security backlog."
    return "Low aggregate risk, with individual findings still requiring review."


def generate_html_report(scan, findings, output_path=None, configuration=None):
    counts = Counter(item.get("severity", "INFO") for item in findings)
    configuration = configuration or {}
    evidence_ids = []
    finding_cards = []
    for index, finding in enumerate(findings):
        severity = finding.get("severity", "INFO").upper()
        evidence_id = f"evidence-{index}"
        evidence_ids.append(evidence_id)
        finding_cards.append(
            f"""
            <article class="finding" data-severity="{escape(severity)}"
                     style="--severity:{SEVERITY_COLORS.get(severity, '#6956C7')}">
              <header>
                <div><span class="badge">{escape(severity)}</span>
                <h3>{escape(finding.get('title', 'Untitled finding'))}</h3></div>
                <strong>CVSS {float(finding.get('cvss_score', 0)):.1f}</strong>
              </header>
              <div class="meta">
                <span>{escape(finding.get('scanner', 'unknown').upper())}</span>
                <span>{escape(finding.get('url', ''))}</span>
              </div>
              <h4>Description</h4>
              <p>{escape(finding.get('description', ''))}</p>
              <h4>Evidence</h4>
              <div class="evidence"><button onclick="copyEvidence('{evidence_id}', this)">Copy</button>
                <pre id="{evidence_id}">{escape(finding.get('evidence', ''))}</pre>
              </div>
              <h4>Remediation</h4>
              <p>{escape(finding.get('remediation', ''))}</p>
              <footer>
                <span class="tag">OWASP {escape(finding.get('owasp', 'Unmapped'))}</span>
                <span class="tag">MITRE {escape(finding.get('mitre', 'Not mapped'))}</span>
              </footer>
            </article>
            """
        )
    mapping_rows = []
    for category in OWASP_TOP_10:
        count = sum(1 for item in findings if category in item.get("owasp", ""))
        mapping_rows.append(
            f"<tr><td>{escape(category)}</td><td>{count}</td>"
            f"<td class=\"{'covered' if count else 'clear'}\">{'Findings present' if count else 'No findings'}</td></tr>"
        )
    top_findings = "".join(
        f"<li><strong>{escape(item.get('severity', 'INFO'))}</strong> "
        f"{escape(item.get('title', ''))}</li>"
        for item in findings[:3]
    ) or "<li>No findings were recorded.</li>"
    filter_buttons = "".join(
        f"<button onclick=\"filterFindings('{severity}',this)\" "
        f"style=\"border-color:{color};color:{color}\">{severity}</button>"
        for severity, color in SEVERITY_COLORS.items()
    )
    urls = sorted({item.get("url", "") for item in findings if item.get("url")})
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    embedded = json.dumps(
        {
            "scan_id": scan.get("id"),
            "target": scan.get("target"),
            "counts": dict(counts),
        }
    ).replace("</", "<\\/")
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bug Hunter Pro Report - {escape(scan.get('target', 'Target'))}</title>
<style>
:root{{--bg:#F4F7FB;--secondary:#EEF3F8;--card:#FFFFFF;--border:#D8E1EC;--cyan:#0F766E;--violet:#6956C7;--orange:#D65A16;--critical:#D92D20;--amber:#B7791F;--success:#168F67;--text:#1E293B;--muted:#526079}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Arial,sans-serif;line-height:1.6}}
h1,h2,h3,h4,.mono,.badge,button{{font-family:"JetBrains Mono",Consolas,monospace}} .page{{max-width:1120px;margin:auto;padding:48px 28px}}
.cover{{min-height:80vh;display:grid;align-content:center;border-left:3px solid var(--cyan);padding-left:42px;background:linear-gradient(135deg,rgba(15,118,110,.07),rgba(255,255,255,.9) 55%)}}
.eyebrow{{color:var(--cyan);letter-spacing:.18em}} h1{{font-size:clamp(42px,8vw,84px);line-height:1;margin:10px 0}} h2{{color:var(--cyan);margin-top:50px}}
.risk{{width:190px;height:190px;border-radius:50%;display:grid;place-content:center;text-align:center;margin:30px 0;background:conic-gradient(var(--cyan) {float(scan.get('risk_score',0))*10}%,var(--border) 0);position:relative}}
.risk:before{{content:"";position:absolute;inset:16px;border-radius:50%;background:var(--card)}} .risk strong,.risk span{{z-index:1}} .risk strong{{font:42px "JetBrains Mono",monospace}}
.notice{{border:1px solid var(--orange);padding:14px;color:var(--orange);max-width:760px}} .grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}}
.stat,.panel,.finding{{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--cyan);padding:20px;margin:16px 0;border-radius:6px;box-shadow:0 8px 24px rgba(30,41,59,.06)}}
.stat strong{{display:block;font:30px "JetBrains Mono",monospace}} .stat span{{color:var(--muted)}} .finding{{border-left-color:var(--severity)}}
.finding header,.finding header>div,.meta,.finding footer,.filters{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}} .finding header{{justify-content:space-between}}
.finding h3{{display:inline;margin:0}} .badge{{border:1px solid var(--severity);color:var(--severity);padding:3px 8px;font-size:12px}}
.meta{{font-size:13px;color:var(--muted);margin:10px 0}} .evidence{{position:relative;background:#F1F5F9;border:1px solid var(--border);padding:16px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:var(--cyan);margin:0}} button{{background:transparent;border:1px solid var(--cyan);color:var(--cyan);padding:8px 13px;cursor:pointer;border-radius:3px}}
button:hover,button.active{{background:rgba(15,118,110,.08)}} .evidence button{{position:absolute;right:8px;top:8px}} .tag{{border:1px solid #C9C0F0;color:#5845B5;background:#F3F0FF;padding:3px 8px;font-size:12px}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:12px;border:1px solid var(--border);text-align:left}} th{{color:var(--cyan);background:var(--secondary)}} tr:nth-child(even){{background:#F8FAFC}}
.covered{{color:var(--critical)}} .clear{{color:var(--success)}} ul{{padding-left:20px}} code{{color:var(--cyan)}} .muted{{color:var(--muted)}} 
@media(max-width:760px){{.grid{{grid-template-columns:1fr 1fr}}.page{{padding:28px 16px}}}}
@media print{{body{{background:white;color:#1E293B}}.page{{max-width:none;padding:20px}}.cover{{min-height:90vh;page-break-after:always}}.finding{{break-inside:avoid;background:white}}button,.filters{{display:none}}.panel,.stat{{background:white}}pre{{color:#1E293B}}}}
</style>
</head>
<body>
<main class="page">
  <section class="cover">
    <div class="eyebrow">AUTHORIZED SECURITY ASSESSMENT</div>
    <h1>BUG HUNTER PRO</h1>
    <p class="mono">Vulnerability Assessment Report</p>
    <p><strong>Target:</strong> {escape(scan.get('target',''))}<br>
       <strong>Scan type:</strong> {escape(scan.get('scan_type','all'))}<br>
       <strong>Generated:</strong> {generated}</p>
    <div class="risk"><strong>{float(scan.get('risk_score',0)):.1f}</strong><span>RISK / 10</span></div>
    <p class="notice">CONFIDENTIAL. This report is intended only for the organization that authorized the assessment. Test only systems you own or have explicit permission to assess.</p>
  </section>

  <section>
    <h2>Executive Summary</h2>
    <div class="grid">
      {''.join(f'<div class="stat" style="border-left-color:{SEVERITY_COLORS[s]}"><strong>{counts[s]}</strong><span>{s.title()}</span></div>' for s in SEVERITY_COLORS)}
    </div>
    <div class="panel"><h3>Risk posture: {float(scan.get('risk_score',0)):.1f}/10</h3><p>{_risk_description(scan.get('risk_score',0))}</p>
      <h4>Top priorities</h4><ol>{top_findings}</ol>
      <p class="muted">Scope: {escape(scan.get('target',''))} | Started: {escape(str(scan.get('started_at','')))} | Completed: {escape(str(scan.get('completed_at','')))}</p>
    </div>
  </section>

  <section>
    <h2>Detailed Findings</h2>
    <div class="filters">
      <button class="active" onclick="filterFindings('ALL',this)">ALL</button>
      {filter_buttons}
    </div>
    <div id="findings">{''.join(finding_cards) or '<div class="panel">No findings were recorded.</div>'}</div>
  </section>

  <section>
    <h2>OWASP Top 10 Mapping</h2>
    <table><thead><tr><th>Category</th><th>Findings</th><th>Status</th></tr></thead><tbody>{''.join(mapping_rows)}</tbody></table>
  </section>

  <section>
    <h2>Appendix</h2>
    <div class="panel"><h3>URLs and endpoints assessed</h3><ul>{''.join(f'<li><code>{escape(url)}</code></li>' for url in urls) or '<li>No finding URLs recorded.</li>'}</ul>
    <h3>Scan configuration</h3><pre>{escape(json.dumps(configuration, indent=2, default=str))}</pre>
    <p>Bug Hunter Pro version {escape(config.APP_VERSION)}. Automated findings require human validation and may include false positives.</p></div>
  </section>
</main>
<script type="application/json" id="report-data">{embedded}</script>
<script>
function filterFindings(severity,button){{
  document.querySelectorAll('.filters button').forEach(item=>item.classList.remove('active'));
  button.classList.add('active');
  document.querySelectorAll('.finding').forEach(item=>{{
    item.style.display=severity==='ALL'||item.dataset.severity===severity?'block':'none';
  }});
}}
async function copyEvidence(id,button){{
  const text=document.getElementById(id).innerText;
  try{{await navigator.clipboard.writeText(text)}}catch(error){{
    const area=document.createElement('textarea');area.value=text;document.body.appendChild(area);area.select();document.execCommand('copy');area.remove();
  }}
  const original=button.textContent;button.textContent='Copied';setTimeout(()=>button.textContent=original,1200);
}}
</script>
</body>
</html>"""
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(html)
    return html
