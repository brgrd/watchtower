"""HTML rendering helpers for Watchtower reports."""

import html
import json
from datetime import datetime, timedelta, timezone

from agent.ingest import placeholder_mode
from agent.scoring import (
    _TAXONOMY,
    _derive_priority,
    _heatmap_cell_color,
    _is_exploitish,
)


def _build_history_accordion(days: list, today_str: str = "") -> str:
    if not days:
        return '<div class="history-panel muted" style="font-size:.78rem;padding:.4rem 0">No briefing history available yet.</div>'
    items = []
    for day in days:
        date_str = day["date_str"]
        ts_str = day["ts_str"]
        cards = day["cards"]
        count = len(cards)
        p1 = sum(1 for c in cards if _derive_priority(c) == "P1")
        exploited = sum(1 for c in cards if _is_exploitish(c))
        meta_txt = " · ".join(
            p
            for p in [
                f"{count} finding{'s' if count != 1 else ''}",
                f"P1: {p1}" if p1 else "",
                f"exploited: {exploited}" if exploited else "",
            ]
            if p
        )
        open_attr = " open" if date_str == today_str else ""
        items.append(
            f'<details class="ha-day"{open_attr}><summary class="ha-summary">'
            f'<span class="ha-date">{html.escape(date_str)}</span>'
            f'<span class="ha-meta">{html.escape(meta_txt)}</span>'
            f'<span class="ha-ts">{html.escape(ts_str)}</span>'
            "</summary></details>"
        )
    return (
        '<section class="panel ha-section"><h3 style="margin:.2rem 0 .5rem">7-Day Briefing History</h3>'
        + "".join(items)
        + "</section>"
    )


def _build_weekly_section(aggregate: dict) -> str:
    if not aggregate or aggregate.get("total_cards", 0) == 0:
        return ""
    total = aggregate.get("total_cards", 0)
    unique_cves = aggregate.get("unique_cves", 0)
    n_domains = len(aggregate.get("active_domains", []))
    most_active = aggregate.get("most_active_day", "—")
    window = aggregate.get("window_days", 7)
    summary_txt = aggregate.get("weekly_summary", "")
    summary_html = (
        f'<p class="weekly-review-text">{html.escape(summary_txt)}</p>'
        if summary_txt
        else '<p class="weekly-review-text muted">Week-in-review will appear after the next Groq analysis.</p>'
    )
    return (
        '<section class="panel weekly-scope">'
        f'<h3 style="margin:.2rem 0 .6rem">{window}-Day Weekly Scope</h3>'
        '<div class="weekly-kpi-row">'
        f'<div class="wkpi"><span class="wk">Total Findings</span><span class="wv">{total}</span></div>'
        f'<div class="wkpi"><span class="wk">Unique CVEs</span><span class="wv">{unique_cves}</span></div>'
        f'<div class="wkpi"><span class="wk">Active Domains</span><span class="wv">{n_domains}</span></div>'
        f'<div class="wkpi"><span class="wk">Most Active Day</span><span class="wv wv-sm">{html.escape(most_active)}</span></div>'
        "</div>" + summary_html + "</section>"
    )


def _write_index_html(
    path: str,
    cards: list,
    heatmap: dict,
    ts: str,
    executive: str = "",
    history: list = None,
    since_hours: int = 6,
    groq_status: str = "unknown",
    delta: dict = None,
    history_days: list = None,
    weekly_html: str = "",
):
    total_findings = len(cards)
    p1_count = sum(1 for c in cards if _derive_priority(c) == "P1")
    exploited_count = sum(1 for c in cards if _is_exploitish(c))

    rows = ""
    for c in cards:
        links = "".join(
            f'<li><a href="{html.escape(s["url"])}" target="_blank" rel="noopener noreferrer">{html.escape(s["title"])}</a></li>'
            for s in c["sources"].get("primary", [])
        )
        badge_bg, badge_fg = _heatmap_cell_color(int(c.get("risk_score", 0)), 1)
        pri = _derive_priority(c)
        pri_cls = "p1" if pri == "P1" else "p2" if pri == "P2" else "p3"
        tags = " ".join(
            f'<span class="domain-tag">{html.escape(_TAXONOMY.get(d, {}).get("label", d))}</span>'
            for d in c.get("domains", [])
            if d != "uncategorised"
        )
        domains_attr = " ".join(c.get("domains", []))
        rows += f"""
                <details class="cluster" data-domains="{html.escape(domains_attr)}">
                    <summary>
                        <span class="badge" style="background:{badge_bg};color:{badge_fg}">{int(c.get('risk_score', 0))}</span>
                        <span class="priority {pri_cls}">{pri}</span>
                        {html.escape(c.get('title', ''))}
                        <div class="domain-tags" style="margin:0 0 0 .5rem;display:inline">{tags}</div>
                    </summary>
                    <div class="cluster-body">
                        <p>{html.escape(c.get('summary', ''))}</p>
                        <ul>{links}</ul>
                    </div>
                </details>"""

    card_data = [
        {
            "title": c.get("title", ""),
            "risk_score": int(c.get("risk_score", 0)),
            "priority": _derive_priority(c),
            "domains": c.get("domains", []),
            "summary": c.get("summary", ""),
        }
        for c in cards
    ]

    _today_et = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%d")
    history_section = _build_history_accordion(history_days or [], today_str=_today_et)

    page_html = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Watchtower — InfraSec Briefing</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0f0f0f;color:#c9d1d9;margin:0}}
.header-bar{{padding:1rem;border-bottom:1px solid #333}}
.app-main{{padding:1rem;max-width:1320px;margin:0 auto}}
.panel{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.7rem .8rem}}
.cluster{{background:#151515;border:1px solid #2a2a2a;border-radius:6px;margin:.55rem 0}}
.cluster summary{{padding:.62rem .85rem;cursor:pointer}}
.cluster-body{{padding:.2rem .9rem .85rem}}
.badge{{border-radius:999px;padding:2px 8px;font-size:.72rem;font-weight:700;margin-right:.35rem}}
.priority{{border-radius:999px;padding:2px 8px;font-size:.68rem;font-weight:800;margin-right:.3rem;border:1px solid #333}}
.right-rail{{position:fixed;right:0;top:0;bottom:0;width:360px;background:#1a1a1a;border-left:1px solid #2a2a2a;padding:.8rem .7rem}}
.rail-tablist{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin:.1rem 0 .2rem}}
.rail-tab{{border:1px solid #333;background:#181818;color:#999;font-size:.68rem;padding:.24rem .2rem;border-radius:4px;text-align:center;cursor:pointer}}
.rail-panel{{display:none}} .rail-panel.active{{display:block}}
.rail-handle{{position:absolute;left:-4px;top:0;bottom:0;width:8px;cursor:ew-resize}}
.kpi-grid{{display:grid;grid-template-columns:repeat(3,minmax(110px,1fr));gap:8px}}
.kpi{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.55rem .7rem}}
</style>
</head>
<body>
<div class=\"rail-backdrop\" id=\"rail-backdrop\"></div>
<button id=\"rail-mobile-toggle\" class=\"rail-mobile-toggle\" type=\"button\" aria-controls=\"domain-rail\" aria-expanded=\"false\">Domain Activity</button>
<header class=\"header-bar\">
  <h1>Watchtower — Infrastructure Security Briefing</h1>
  <p>Generated <strong>{ts.replace('_', ' ')}</strong> UTC | <a href=\"latest.md\">latest.md</a><span class=\"next-run\" id=\"next-run-cd\">Next run —</span></p>
</header>
<main class=\"app-main\">
{f'<div class="executive"><h2>Analyst Summary</h2><p>{html.escape(executive)}</p></div>' if executive else ''}
<section class=\"kpi-grid\">
<div class=\"kpi\"><strong>Findings</strong> {total_findings}</div>
<div class=\"kpi\"><strong>P1</strong> {p1_count}</div>
<div class=\"kpi\"><strong>Exploited</strong> {exploited_count}</div>
</section>
{history_section}
{weekly_html}
<h2>Top Findings</h2>
{rows}
<footer>Watchtower · placeholder mode: {str(placeholder_mode()).lower()}</footer>
</main>
<aside id=\"domain-rail\" class=\"panel right-rail\" role=\"complementary\" aria-label=\"Domain Activity\">
  <div class=\"rail-handle\" id=\"rail-handle\" role=\"separator\"></div>
  <div class=\"rail-header\"><h3>Domain Activity</h3><div class=\"rail-actions\"><button id=\"rail-toggle\" class=\"rail-btn\">Collapse</button><button id=\"rail-close\" class=\"rail-btn\" style=\"display:none\">Close</button></div></div>
  <div class=\"rail-content\" id=\"rail-content\">
    <div class=\"rail-tablist\" role=\"tablist\">
      <button class=\"rail-tab\" type=\"button\" id=\"tab-overview\" role=\"tab\" aria-controls=\"panel-overview\" aria-selected=\"true\" data-tab=\"overview\">Overview</button>
      <button class=\"rail-tab\" type=\"button\" id=\"tab-feeds\" role=\"tab\" aria-controls=\"panel-feeds\" aria-selected=\"false\" data-tab=\"feeds\">Feeds</button>
      <button class=\"rail-tab\" type=\"button\" id=\"tab-alerts\" role=\"tab\" aria-controls=\"panel-alerts\" aria-selected=\"false\" data-tab=\"alerts\">Alerts</button>
      <button class=\"rail-tab\" type=\"button\" id=\"tab-forensics\" role=\"tab\" aria-controls=\"panel-forensics\" aria-selected=\"false\" data-tab=\"forensics\">Forensics</button>
    </div>
    <section class=\"rail-panel active\" id=\"panel-overview\" role=\"tabpanel\" aria-labelledby=\"tab-overview\"><div id=\"tm-detail\">Click a node to inspect findings.</div></section>
    <section class=\"rail-panel\" id=\"panel-feeds\" role=\"tabpanel\" aria-labelledby=\"tab-feeds\"></section>
    <section class=\"rail-panel\" id=\"panel-alerts\" role=\"tabpanel\" aria-labelledby=\"tab-alerts\"></section>
    <section class=\"rail-panel\" id=\"panel-forensics\" role=\"tabpanel\" aria-labelledby=\"tab-forensics\"></section>
  </div>
</aside>
<script>
var CARDS={json.dumps(card_data)};
var CURRENT_DOMAIN='all';
var DOMAIN_LABELS={json.dumps({k: v.get('label', k) for k, v in heatmap.items()})};
var WT_TELEMETRY=[];
function trackUi(evt,payload){{WT_TELEMETRY.push({{event:evt,ts:new Date().toISOString(),payload:payload||{{}}}});}}
function applyRailWidth(w){{try{{localStorage.setItem('wt.rail.width',String(w||360));}}catch(e){{}}}}
function setRailCollapsed(collapsed,persist){{try{{localStorage.setItem('wt.rail.collapsed',collapsed?'1':'0');}}catch(e){{}}}}
function setRailTab(tab){{try{{localStorage.setItem('wt.rail.tab',tab);}}catch(e){{}}}}
function initRightRail(){{
  var handle=document.getElementById('rail-handle');
    if(handle){{
        handle.addEventListener('pointerdown',function(){{trackUi('rail_resize_start');}});
        handle.addEventListener('pointerup',function(){{trackUi('rail_resized');}});
    }}
}}
function selectDomain(domain){{
  CURRENT_DOMAIN = domain||'all';
  var subset=CURRENT_DOMAIN==='all'?CARDS:CARDS.filter(function(c){{return(c.domains||[]).indexOf(CURRENT_DOMAIN)>=0;}});
  var p1=subset.filter(function(c){{return c.priority==='P1';}}).length;
  var maxRisk=subset.reduce(function(m,c){{return Math.max(m,c.risk_score||0);}},0);
  var lbl=DOMAIN_LABELS[domain]||domain||'All domains';
  var t=document.getElementById('tm-detail');
  if(t){{t.innerHTML='<strong>'+lbl+'</strong><div>Findings: '+subset.length+' · P1: '+p1+' · Max risk: '+maxRisk+'</div>';}}
  trackUi('domain_selected',{{domain:CURRENT_DOMAIN,count:subset.length,maxRisk:maxRisk}});
}}
(function(){{
  var el=document.getElementById('next-run-cd');
  if(!el)return;
  function tick(){{el.textContent='Next run --:--:--';}}
  tick();
}})();
initRightRail();
selectDomain('all');
</script>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(page_html)
