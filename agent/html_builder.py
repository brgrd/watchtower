"""HTML builder — threat-map SVG, calendar, history accordion, full briefing page.

All pure-HTML/SVG rendering functions extracted from runner.py.
Import via:  ``from agent import html_builder as html_builder_mod``
"""

import html
import json
from collections import Counter
from datetime import datetime, timedelta, timezone

import tldextract

from agent.ingest import placeholder_mode
from agent.scoring import (
    _TAXONOMY,
    _derive_priority,
    _extract_cves,
    _heatmap_cell_color,
    _is_exploitish,
)


# ──────────────────────────────────────────────
# Threat constellation map — Python-rendered SVG
# ──────────────────────────────────────────────

_TM_NODES: dict = {
    # key: (cx, cy, display_label)   — radial mesh, no dominant axis
    "ai_threat": (680, 68, "AI / ML Threats"),
    "identity": (534, 132, "Identity / Auth"),
    "ca_trust": (345, 184, "CA / PKI"),
    "cloud_iam": (737, 197, "Cloud / IAM"),
    "crypto_lib": (180, 329, "Crypto Libs"),
    "web_framework": (478, 342, "Web / Servers"),
    "container": (659, 360, "Containers"),
    "browser_ext": (847, 307, "Browser Ext"),
    "os_kernel": (337, 460, "OS / Kernel"),
    "supply_chain": (119, 471, "Supply Chain"),
    "pkg_npm": (221, 583, "npm / Node"),
    "pkg_pypi": (381, 609, "PyPI / Python"),
    "pkg_maven": (534, 623, "Maven / Java"),
    "pkg_nuget": (690, 570, ".NET / NuGet"),
    "pkg_gem": (806, 473, "RubyGems"),
    "uncategorised": (858, 171, "Other"),
}

_TM_EDGES: list = [
    ("ai_threat", "cloud_iam"),
    ("ai_threat", "supply_chain"),
    ("ai_threat", "identity"),
    ("supply_chain", "pkg_npm"),
    ("supply_chain", "pkg_pypi"),
    ("supply_chain", "pkg_maven"),
    ("supply_chain", "pkg_nuget"),
    ("supply_chain", "pkg_gem"),
    ("supply_chain", "cloud_iam"),
    ("supply_chain", "identity"),
    ("pkg_npm", "web_framework"),
    ("pkg_npm", "os_kernel"),
    ("pkg_pypi", "web_framework"),
    ("pkg_maven", "web_framework"),
    ("pkg_nuget", "web_framework"),
    ("pkg_gem", "web_framework"),
    ("pkg_gem", "container"),
    ("web_framework", "os_kernel"),
    ("web_framework", "container"),
    ("web_framework", "cloud_iam"),
    ("web_framework", "identity"),
    ("os_kernel", "crypto_lib"),
    ("os_kernel", "container"),
    ("container", "cloud_iam"),
    ("container", "crypto_lib"),
    ("cloud_iam", "identity"),
    ("cloud_iam", "ca_trust"),
    ("identity", "ca_trust"),
    ("identity", "browser_ext"),
    ("ca_trust", "crypto_lib"),
    ("browser_ext", "cloud_iam"),
    ("browser_ext", "ca_trust"),
]


def _sparkline_svg(
    values: list, width: int = 80, height: int = 22, color: str = "#0366d6"
) -> str:
    if len(values) < 2:
        return f'<span style="font-size:.8rem;color:#57606a">{values[-1] if values else 0}</span>'
    mn, mx = min(values), max(values)
    rng = mx - mn or 1
    pad = 2
    step = width / max(len(values) - 1, 1)
    pts = " ".join(
        f"{i * step:.1f},{height - pad - (v - mn) / rng * (height - pad * 2):.1f}"
        for i, v in enumerate(values)
    )
    lx = (len(values) - 1) * step
    ly = height - pad - (values[-1] - mn) / rng * (height - pad * 2)
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"'
        f' style="vertical-align:middle;overflow:visible">'
        f'<polyline points="{pts}" fill="none" stroke="{color}"'
        f' stroke-width="1.5" stroke-linejoin="round"/>'
        f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="2.5" fill="{color}"/>'
        f"</svg>"
    )


def _build_threat_map_svg(cards: list, heatmap: dict, velocity: dict = None) -> str:
    """Return an inline SVG constellation threat map, heat-coloured by domain activity."""
    # Raw per-domain heat score
    raw: dict[str, int] = {}
    cnts: dict[str, int] = {}
    for key in _TM_NODES:
        sub = [c for c in cards if key in c.get("domains", [])]
        cnt = len(sub)
        cnts[key] = cnt
        mx = max((c.get("risk_score", 0) for c in sub), default=0)
        p1 = sum(1 for c in sub if str(c.get("priority", "")).upper() == "P1")
        ex = sum(1 for c in sub if _is_exploitish(c))
        raw[key] = min(
            100,
            round(
                cnt * 8
                + mx * 0.55
                + (p1 / cnt * 24 if cnt else 0)
                + (ex / cnt * 18 if cnt else 0)
            ),
        )

    # Ambient heat: neighbours bleed 20 % of their score
    nbrs: dict[str, list] = {k: [] for k in _TM_NODES}
    for a, b in _TM_EDGES:
        if a in nbrs and b in nbrs:
            nbrs[a].append(b)
            nbrs[b].append(a)
    scores: dict[str, int] = {}
    for key in _TM_NODES:
        nb_max = max((raw[n] for n in nbrs[key] if n in raw), default=0)
        scores[key] = max(raw[key], int(nb_max * 0.08))

    def _heat(s: int):
        """Dark-center aura: outer bloom behind opaque disc, edge ring on perimeter."""
        t = max(0.06, s / 100.0)
        bloom_op = round(0.18 + t * 0.55, 3)  # outer aura fill: 0.18 → 0.73
        ring_op = round(0.35 + t * 0.50, 3)  # edge ring stroke: 0.35 → 0.85
        if s >= 85:
            bloom = f"rgba(255,40,40,{bloom_op})"
            ring = f"rgba(255,80,80,{ring_op})"
        else:
            bloom = f"rgba(200,200,200,{bloom_op})"
            ring = f"rgba(220,220,220,{ring_op})"
        return bloom, ring

    def _edge_style(sa: int, sb: int):
        s = max(sa, sb)
        t = min(1.0, s / 100.0)
        glow_op = round(0.10 + t * 0.40, 3)  # blurred glow behind: 0.10 → 0.50
        line_op = round(0.18 + t * 0.45, 3)  # crisp line on top:   0.18 → 0.63
        return glow_op, line_op

    W, H = 960, 760
    p: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        'preserveAspectRatio="xMidYMid meet" '
        'style="width:100%;height:auto;display:block;background:#0a0a0a;border-radius:8px;border:1px solid #333">',
        "<defs>",
        '<filter id="f-outer" x="-300%" y="-300%" width="700%" height="700%">'
        '<feGaussianBlur stdDeviation="18"/>'
        "</filter>",
        '<filter id="f-mid" x="-150%" y="-150%" width="400%" height="400%">'
        '<feGaussianBlur stdDeviation="7"/>'
        "</filter>",
        '<filter id="edge-glow" x="-100%" y="-100%" width="300%" height="300%">'
        '<feGaussianBlur stdDeviation="4"/>'
        "</filter>",
        "</defs>",
    ]
    # Subtle background grid dots
    p.append('<g opacity="0.03">')
    for gx in range(44, W, 62):
        for gy in range(32, H, 62):
            p.append(f'<circle cx="{gx}" cy="{gy}" r="1" fill="#666"/>')
    p.append("</g>")

    # Edges — glow pass first (behind), crisp line pass on top
    for a, b in _TM_EDGES:
        if a not in _TM_NODES or b not in _TM_NODES:
            continue
        ax, ay, _ = _TM_NODES[a]
        bx, by, _ = _TM_NODES[b]
        glow_op, _ = _edge_style(scores[a], scores[b])
        p.append(
            f'<line x1="{ax}" y1="{ay}" x2="{bx}" y2="{by}" '
            f'stroke="rgba(150,150,150,{glow_op:.3f})" stroke-width="4.5" '
            f'stroke-linecap="round" filter="url(#edge-glow)"/>'
        )
    for a, b in _TM_EDGES:
        if a not in _TM_NODES or b not in _TM_NODES:
            continue
        ax, ay, _ = _TM_NODES[a]
        bx, by, _ = _TM_NODES[b]
        _, line_op = _edge_style(scores[a], scores[b])
        p.append(
            f'<line x1="{ax}" y1="{ay}" x2="{bx}" y2="{by}" '
            f'stroke="rgba(180,180,180,{line_op:.3f})" stroke-width="1.0" '
            f'stroke-linecap="round"/>'
        )

    # Nodes
    node_id = 0
    _vel = velocity or {}
    for key, (cx, cy, lbl) in _TM_NODES.items():
        s = scores[key]
        outer, ring_color = _heat(s)
        R = 24
        lf = "#e6e6e6" if s >= 20 else "#888"
        _accel_glow = (
            f'<circle cx="{cx}" cy="{cy}" r="{R+20}" '
            f'fill="rgba(220,120,30,0.09)" filter="url(#f-outer)"/>'
            if _vel.get(key) == "\u2191\u21911"
            else ""
        )

        p.append(
            f'<g class="tm-node" data-domain="{key}" '
            f'onclick="selectDomain(\'{key}\')" style="cursor:pointer">'
        )
        # Velocity acceleration glow (orange halo for accelerating domains)
        if _accel_glow:
            p.append(_accel_glow)
        # Layer 1: Outer aura — large fill, heavy blur, sits BEHIND disc
        p.append(
            f'<circle cx="{cx}" cy="{cy}" r="{R+14}" fill="{outer}" filter="url(#f-outer)"/>'
        )
        # Layer 2: Opaque dark disc — covers center so only perimeter glow shows
        p.append(
            f'<circle class="node-disc" cx="{cx}" cy="{cy}" r="{R}" '
            f'fill="rgba(15,15,15,0.95)" stroke="rgba(100,100,100,0.20)" stroke-width="0.6"/>'
        )
        # Layer 3: Edge ring — stroke-only at disc radius, medium blur, glows outward from rim
        p.append(
            f'<circle cx="{cx}" cy="{cy}" r="{R}" '
            f'fill="none" stroke="{ring_color}" stroke-width="3.5" filter="url(#f-mid)"/>'
        )
        # Count label inside disc — only when findings exist for this domain
        _cnt = cnts.get(key, 0)
        if _cnt > 0:
            _cnt_txt = "9+" if _cnt > 9 else str(_cnt)
            p.append(
                f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" dominant-baseline="middle" '
                f'font-family="system-ui,sans-serif" font-size="11" font-weight="700" '
                f'fill="{lf}" opacity="0.9">{_cnt_txt}</text>'
            )
        # Selection ring — simple white ring, hidden at rest
        p.append(
            f'<circle class="sel-indicator" cx="{cx}" cy="{cy}" r="{R+5}" '
            f'fill="none" stroke="rgba(255,255,255,0.65)" stroke-width="1.5"/>'
        )
        # Label
        ly = cy + R + 13
        p.append(
            f'<text x="{cx}" y="{ly}" text-anchor="middle" '
            f'font-family="system-ui,sans-serif" font-size="10" font-weight="600" '
            f'fill="{lf}" stroke="#0f0f0f" stroke-width="2.5" paint-order="stroke fill">{lbl}</text>'
        )
        p.append("</g>")
        node_id += 1

    p.append("</svg>")
    return "\n".join(p)


def _compute_velocity(history_days: list) -> dict:
    """Return {domain_key: accel_label} for domains with notable acceleration.
    accel_label is one of '\u2191\u21911', '\u21911', '\u21931' (rising fast, rising, falling).
    Requires at least 4 days of history; returns {} otherwise.
    """
    if not history_days or len(history_days) < 4:
        return {}
    # history_days is sorted newest-first; take up to 7
    days = list(reversed(history_days[:7]))  # oldest-first for computation
    domain_series: dict = {k: [] for k in _TM_NODES}
    for day in days:
        day_cards = day.get("cards", [])
        for key in domain_series:
            domain_series[key].append(
                sum(1 for c in day_cards if key in c.get("domains", []))
            )
    result = {}
    for key, series in domain_series.items():
        if len(series) < 4:
            continue
        recent = sum(series[-2:]) / 2
        prior = sum(series[-4:-2]) / 2
        delta = recent - prior
        if delta >= 3:
            result[key] = "\u2191\u21911"  # ↑↑
        elif delta >= 1.5:
            result[key] = "\u21911"  # ↑
        elif delta <= -1.5:
            result[key] = "\u21931"  # ↓
    return result


def _build_domain_rank_html(cards: list, heatmap: dict, velocity: dict = None) -> str:
    """Ranked domain bar list for the threat map side panel."""
    velocity = velocity or {}
    rows: list[str] = []
    domain_scores: list[tuple] = []
    for key, (_, _, lbl) in _TM_NODES.items():
        sub = [c for c in cards if key in c.get("domains", [])]
        cnt = len(sub)
        mx = max((c.get("risk_score", 0) for c in sub), default=0)
        p1 = sum(1 for c in sub if str(c.get("priority", "")).upper() == "P1")
        ex = sum(1 for c in sub if _is_exploitish(c))
        sc = min(
            100,
            round(
                cnt * 8
                + mx * 0.55
                + (p1 / cnt * 24 if cnt else 0)
                + (ex / cnt * 18 if cnt else 0)
            ),
        )
        domain_scores.append((sc, cnt, key, lbl))

    domain_scores.sort(reverse=True)
    bar_colors = ["#1c2e42", "#223450", "#283e5e", "#2e4a6e", "#5a1a1a"]

    for sc, cnt, key, lbl in domain_scores:
        if sc == 0 and cnt == 0:
            continue
        pct = sc
        bidx = 0 if sc < 18 else 1 if sc < 38 else 2 if sc < 62 else 3 if sc < 82 else 4
        bcol = bar_colors[bidx]
        lc = "#8a3030" if sc >= 85 else "#6a8898"
        vc = "#5a2020" if sc >= 85 else "#3a5568"
        vel = velocity.get(key, "")
        vel_html = (
            f'<span class="vel-chip vel-up2" title="Accelerating">{vel}</span>'
            if vel == "\u2191\u21911"
            else (
                f'<span class="vel-chip vel-up1" title="Rising">{vel}</span>'
                if vel == "\u21911"
                else (
                    f'<span class="vel-chip vel-dn" title="Falling">{vel}</span>'
                    if vel == "\u21931"
                    else ""
                )
            )
        )
        rows.append(
            f'<div class="rank-row" onclick="selectDomain(\'{key}\')">'
            f'<span class="rank-label" style="color:{lc}" title="{lbl}">{lbl}</span>'
            f'<div class="rank-bar-wrap"><div class="rank-bar" style="width:{pct}%;background:{bcol}"></div></div>'
            f'{vel_html}<span class="rank-val" style="color:{vc}">{sc}</span>'
            f"</div>"
        )
    if not rows:
        return '<div class="muted" style="font-size:.78rem;padding:.4rem 0">No active findings in this window.</div>'
    total = len(cards)
    all_row = (
        f'<div class="rank-row rank-row-all" onclick="selectDomain(\'all\')" style="border-bottom:1px solid #252525;margin-bottom:.35rem;padding-bottom:.35rem">'
        f'<span class="rank-label" style="color:#c9d1d9;font-weight:700">All Domains</span>'
        f'<div class="rank-bar-wrap"></div>'
        f'<span class="rank-val" style="color:#c9d1d9;font-weight:700">{total}</span>'
        f"</div>"
    )
    return all_row + "".join(rows)


# -----------------------------
# P3: 7-day history helpers
# -----------------------------
def _build_history_accordion(days: list, today_str: str = "") -> str:
    """Build a 7-day briefing history accordion `<section>` element.

    Each day dict may carry pre-computed lifecycle counts (added by
    _annotate_history_lifecycle in runner.py):
      still_active, resolved, escalated
    """
    if not days:
        return (
            '<div class="history-panel muted" style="font-size:.78rem;padding:.4rem 0">'
            "No briefing history available yet.</div>"
        )
    items: list[str] = []
    for day in days:
        date_str = day["date_str"]
        ts_str = day["ts_str"]
        cards = day["cards"]
        count = len(cards)
        p1 = sum(1 for c in cards if _derive_priority(c) == "P1")
        exploited = sum(1 for c in cards if _is_exploitish(c))
        meta_parts = [f"{count} finding{'s' if count != 1 else ''}"]
        if p1:
            meta_parts.append(f"P1: {p1}")
        if exploited:
            meta_parts.append(f"exploited: {exploited}")
        meta_txt = " \u00b7 ".join(meta_parts)

        # Lifecycle badges (present when _annotate_history_lifecycle has run)
        lifecycle_html = ""
        still_active = day.get("still_active")
        resolved = day.get("resolved")
        escalated = day.get("escalated")
        if still_active is not None:
            lc_parts: list[str] = []
            if still_active > 0:
                lc_parts.append(
                    f'<span class="ha-lc ha-lc--active" title="Still active today">'
                    f'\u25cf\u00a0{still_active} active</span>'
                )
            if resolved > 0:
                lc_parts.append(
                    f'<span class="ha-lc ha-lc--resolved" title="Resolved since this run">'
                    f'\u2713\u00a0{resolved} resolved</span>'
                )
            if escalated > 0:
                lc_parts.append(
                    f'<span class="ha-lc ha-lc--escalated" title="Risk score increased since this run">'
                    f'\u2191\u00a0{escalated} escalated</span>'
                )
            if lc_parts:
                lifecycle_html = (
                    f'<span class="ha-lifecycle">'
                    + " ".join(lc_parts)
                    + "</span>"
                )

        trows_list: list[str] = []
        for c in sorted(cards, key=lambda x: int(x.get("risk_score", 0)), reverse=True):
            pri = _derive_priority(c)
            pri_cls = "p1" if pri == "P1" else "p2" if pri == "P2" else "p3"
            trows_list.append(
                "<tr>"
                f'<td class="ha-title">{html.escape(c.get("title", "")[:80])}</td>'
                f'<td class="ha-risk">{int(c.get("risk_score", 0))}</td>'
                f'<td class="ha-pri"><span class="priority {pri_cls}">{pri}</span></td>'
                "</tr>"
            )
        trows = "".join(trows_list)
        open_attr = " open" if date_str == today_str else ""
        items.append(
            f'<details class="ha-day"{open_attr}>'
            f'<summary class="ha-summary">'
            f'<span class="ha-date">{html.escape(date_str)}</span>'
            f'<span class="ha-meta">{html.escape(meta_txt)}</span>'
            + lifecycle_html
            + f'<span class="ha-ts">{html.escape(ts_str)}</span>'
            f"</summary>"
            f'<div class="ha-body">'
            f'<table class="ha-table"><thead><tr><th>Finding</th><th>Risk</th><th>Pri</th></tr></thead>'
            f"<tbody>{trows}</tbody></table>"
            f"</div>"
            f"</details>"
        )
    return (
        '<section class="panel ha-section">'
        '<h3 style="margin:.2rem 0 .5rem">7-Day Briefing History</h3>'
        + "".join(items)
        + "</section>"
    )


def _build_velocity_sparkline(day_counts: dict) -> str:
    """7-slot polyline SVG from a {date: count} map. Always renders 7 slots."""
    if not day_counts:
        return ""
    sorted_days = sorted(day_counts.keys())[-7:]
    counts = [day_counts.get(d, 0) for d in sorted_days]
    while len(counts) < 7:
        counts.insert(0, 0)
    W, H, PAD = 56, 20, 2
    slot_w = W / 7
    max_c = max(counts) or 1

    def _y(c):
        return round(H - PAD - (c / max_c) * (H - PAD * 2), 1)

    pts = " ".join(f"{slot_w * i + slot_w / 2:.1f},{_y(c)}" for i, c in enumerate(counts))
    dots = "".join(
        f'<circle cx="{slot_w*i+slot_w/2:.1f}" cy="{_y(c)}" r="2.2" '
        f'fill="{"var(--vel-dot,#60a5fa)" if c > 0 else "transparent"}"/>'
        for i, c in enumerate(counts)
    )
    return (
        f'<svg class="vel-spark" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
        f'xmlns="http://www.w3.org/2000/svg" aria-label="Threat velocity \u2014 7 days">'
        f'<polyline points="{pts}" fill="none" stroke="var(--vel-line,#60a5fa)" '
        f'stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>'
        f"{dots}</svg>"
    )


def _build_weekly_section(aggregate: dict, cross_run: dict = None) -> str:
    """Build the weekly scope <section> HTML block."""
    if not aggregate or aggregate.get("total_cards", 0) == 0:
        return ""
    unique_cves = aggregate.get("unique_cves", 0)
    most_active = aggregate.get("most_active_day", "\u2014")
    window = aggregate.get("window_days", 7)
    summary_txt = aggregate.get("weekly_summary", "")
    top_cves = aggregate.get("top_cves", [])
    day_counts = aggregate.get("day_counts", {})
    max_count = top_cves[0]["count"] if top_cves else 1
    cve_rows = "".join(
        "<tr>"
        f'<td class="wcve-id">{html.escape(item["cve"])}</td>'
        f'<td class="wcve-bar-cell"><div class="wcve-bar-inner" style="width:{min(100, round(item["count"] / max_count * 100))}%"></div></td>'
        f'<td class="wcve-count">{item["count"]}</td>'
        "</tr>"
        for item in top_cves
    )
    summary_html = (
        f'<p class="weekly-review-text">{html.escape(summary_txt)}</p>'
        if summary_txt
        else '<p class="weekly-review-text muted">Week-in-review will appear after the next Groq analysis.</p>'
    )
    cve_block = (
        (
            '<details class="wcve-details">'
            f"<summary>Top CVEs this week ({len(top_cves)} tracked)</summary>"
            '<table class="wcve-table"><thead><tr>'
            "<th>CVE</th><th>Frequency</th><th>#</th>"
            "</tr></thead>"
            f"<tbody>{cve_rows}</tbody></table>"
            "</details>"
        )
        if top_cves
        else ""
    )
    window_note = (
        '<span class="weekly-window-note">Building history \u2014 full 7-day view available after day 3</span>'
        if window < 3
        else f'<span class="weekly-window-note">Past {window} day{"s" if window != 1 else ""}</span>'
    )

    # ── KPI tiles ─────────────────────────────────────────────────────────────
    wcr = cross_run or {}

    # Tile 1: Still-Active Rate (cross-run) or total findings fallback
    if wcr.get("history_total"):
        still_n = wcr["still_active"]
        hist_n = wcr["history_total"]
        hist_date = wcr.get("history_date", "")
        tile1 = (
            f'<div class="wkpi" title="Findings from {html.escape(hist_date)} still unresolved today">'
            f'<span class="wk">Still Active</span>'
            f'<span class="wv wv-cross">{still_n}<small>/{hist_n}</small></span>'
            f'<span class="wk-sub">vs {html.escape(hist_date)}</span></div>'
        )
    else:
        total = aggregate.get("total_cards", 0)
        tile1 = (
            f'<div class="wkpi"><span class="wk">Total Findings</span>'
            f'<span class="wv">{total}</span></div>'
        )

    # Tile 2: Patch Coverage Change
    patch_n = wcr.get("patch_improved", 0)
    tile2 = (
        f'<div class="wkpi wkpi--good" title="CVEs that moved from No Fix to Patched/Workaround this week">'
        f'<span class="wk">Patched This Week</span>'
        f'<span class="wv wv-good">+{patch_n}</span>'
        f'<span class="wk-sub">CVEs resolved</span></div>'
    ) if patch_n > 0 else (
        f'<div class="wkpi" title="CVEs that moved from No Fix to Patched/Workaround this week">'
        f'<span class="wk">Patched This Week</span>'
        f'<span class="wv wv-muted">\u2014</span>'
        f'<span class="wk-sub">no change</span></div>'
    )

    # Tile 3: Unique CVEs
    tile3 = (
        f'<div class="wkpi"><span class="wk">Unique CVEs</span>'
        f'<span class="wv">{unique_cves}</span></div>'
    )

    # Tile 4: Threat Velocity sparkline
    sparkline = _build_velocity_sparkline(day_counts)
    tile4 = (
        f'<div class="wkpi wkpi--spark" title="Daily finding count over the past 7 days">'
        f'<span class="wk">Threat Velocity</span>'
        f'<span class="wv-spark">{sparkline}</span></div>'
    ) if sparkline else (
        f'<div class="wkpi"><span class="wk">Most Active Day</span>'
        f'<span class="wv wv-sm">{html.escape(most_active)}</span></div>'
    )

    # Tile 5: Most Active Day
    tile5 = (
        f'<div class="wkpi"><span class="wk">Most Active Day</span>'
        f'<span class="wv wv-sm">{html.escape(most_active)}</span></div>'
    )

    return (
        '<section class="panel weekly-scope">'
        f'<h3 style="margin:.2rem 0 .6rem">Weekly Overview {window_note}</h3>'
        '<div class="weekly-kpi-row">'
        + tile1 + tile2 + tile3 + tile4 + tile5
        + '</div>'
        '<div class="weekly-review-label">Week-in-Review</div>'
        + summary_html
        + cve_block
        + "</section>"
    )


def _build_enrichment_html(enrichment: dict) -> str:
    """Build a collapsed 'Extracted context' block from zero-token source enrichment data."""
    if not enrichment or enrichment.get("source_count", 0) == 0:
        return ""
    parts: list = []
    lede = enrichment.get("lede", "")
    if lede:
        parts.append(f'<p class="enrich-lede">{html.escape(lede)}</p>')
    all_cves = enrichment.get("cves", [])
    extra_cves = enrichment.get("extra_cves", [])
    if all_cves:
        chips = "".join(
            f'<span class="enrich-cve{" enrich-cve--extra" if c in extra_cves else ""}">{html.escape(c)}</span>'
            for c in all_cves[:10]
        )
        parts.append(
            f'<div class="enrich-row"><span class="enrich-label">CVEs</span>{chips}</div>'
        )
    products = enrichment.get("products", [])
    if products:
        chips = "".join(
            f'<span class="enrich-product">{html.escape(p)}</span>'
            for p in products[:8]
        )
        parts.append(
            f'<div class="enrich-row"><span class="enrich-label">Affected</span>{chips}</div>'
        )
    versions = enrichment.get("versions", [])
    if versions:
        chips = "".join(
            f'<span class="enrich-version">{html.escape(v)}</span>'
            for v in versions[:6]
        )
        parts.append(
            f'<div class="enrich-row"><span class="enrich-label">Versions</span>{chips}</div>'
        )
    dates = enrichment.get("dates", [])
    if dates:
        chips = "".join(
            f'<span class="enrich-date">{html.escape(d)}</span>' for d in dates[:4]
        )
        parts.append(
            f'<div class="enrich-row"><span class="enrich-label">Dates</span>{chips}</div>'
        )
    if not parts:
        return ""
    src_count = enrichment.get("source_count", 0)
    inner = "".join(parts)
    return (
        f'<details class="enrich-block">'
        f'<summary class="enrich-summary">&#128269; Extracted context '
        f'<span class="enrich-src-count">{src_count} source{"s" if src_count != 1 else ""}</span>'
        f"</summary>"
        f'<div class="enrich-body">{inner}</div>'
        f"</details>"
    )


def _build_forensics_html(cards: list, ioc_ledger: dict = None) -> str:
    """Build the Forensics rail-tab content: CVE index, kill-chain breakdown,
    affected product matrix, and IOC intelligence panel.

    All four panels are generated from the current-window ``cards`` list and
    the cross-run ``ioc_ledger`` dict.  No network or model calls are made.
    """
    ioc_ledger = ioc_ledger or {}

    _PATCH_RANK = {"patched": 3, "workaround": 2, "no_fix": 1, "unknown": 0}
    _PATCH_LABELS = {
        "patched": ("\u2713 Patched", "#2ea043"),
        "workaround": ("~ Workaround", "#f9c74f"),
        "no_fix": ("\u2717 No Fix", "#d62828"),
        "unknown": ("? Unknown", "#8b949e"),
    }

    # ── Panel A: CVE Reference Index ───────────────────────────────────────────────────
    cve_map: dict = {}
    for card in cards:
        cves = card.get("enrichment", {}).get("cves") or _extract_cves(
            card.get("title", "") + " " + card.get("summary", "")
        )
        ps = card.get("patch_status", "unknown")
        for cve in cves:
            entry = cve_map.setdefault(cve, {"count": 0, "patch_status": "unknown"})
            entry["count"] += 1
            if _PATCH_RANK.get(ps, 0) > _PATCH_RANK.get(entry["patch_status"], 0):
                entry["patch_status"] = ps

    if cve_map:
        cve_rows = []
        for cve, data in sorted(
            cve_map.items(), key=lambda x: x[1]["count"], reverse=True
        )[:30]:
            lbl, col = _PATCH_LABELS.get(data["patch_status"], ("? Unknown", "#8b949e"))
            esc = html.escape(cve)
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{esc}"
            cve_rows.append(
                "<tr><td>"
                + '<a href="'
                + nvd_url
                + '" target="_blank" rel="noopener noreferrer"'
                + ' style="color:#79c0ff;font-family:monospace" onclick="event.stopPropagation()">'
                + esc
                + "</a>"
                + "<button onclick=\"forensicsCveClick('"
                + esc
                + "')\""
                + ' title="Filter findings by this CVE"'
                + ' style="background:none;border:none;color:#58a6ff;cursor:pointer;'
                + 'font-size:.75rem;padding:0 0 0 .4rem;vertical-align:middle;opacity:.7">'
                + "\u2295</button></td>"
                + '<td style="text-align:center">'
                + str(data["count"])
                + "</td>"
                + '<td><span style="color:'
                + col
                + ';font-size:.75rem">'
                + lbl
                + "</span></td></tr>"
            )
        cve_html = (
            '<h4 class="forensics-section-title">CVE Reference Index</h4>'
            '<p class="forensics-hint">Click the CVE ID to open the NVD advisory. '
            "Click \u2295 to filter findings in the Overview tab.</p>"
            '<table class="forensics-table"><thead><tr>'
            "<th>CVE</th><th>Findings</th><th>Patch</th>"
            "</tr></thead><tbody>" + "".join(cve_rows) + "</tbody></table>"
        )
    else:
        cve_html = (
            '<h4 class="forensics-section-title">CVE Reference Index</h4>'
            '<div class="forensics-empty">No CVEs found in this window.</div>'
        )

    # ── Panel B: Kill-Chain Breakdown ─────────────────────────────────────────────────
    tactic_map: dict = {}
    for card in cards:
        tactic = card.get("tactic_name", "")
        if tactic:
            tactic_map.setdefault(tactic, []).append(card)

    _TACTIC_ORDER = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command & Control",
        "Exfiltration",
        "Impact",
    ]
    if tactic_map:
        tactic_rows = []
        for tactic in _TACTIC_ORDER:
            if tactic not in tactic_map:
                continue
            tac_cards = sorted(
                tactic_map[tactic], key=lambda c: c.get("risk_score", 0), reverse=True
            )
            inner = "".join(
                '<div style="padding:.2rem 0;border-bottom:1px solid #1e1e1e;font-size:.75rem">'
                + '<span style="color:#e6edf3">'
                + html.escape(c.get("title", "")[:72])
                + "</span>"
                + (
                    ' <code style="color:#8b949e;font-size:.67rem">'
                    + html.escape(c.get("technique_name", "")[:42])
                    + "</code>"
                    if c.get("technique_name")
                    else ""
                )
                + "</div>"
                for c in tac_cards[:8]
            )
            count = len(tac_cards)
            tactic_rows.append(
                '<details class="forensics-acc"><summary>'
                + '<span class="tactic-chip" style="font-size:.7rem">'
                + html.escape(tactic)
                + "</span>"
                + '<span style="margin-left:.4rem;color:#8b949e;font-size:.72rem">'
                + str(count)
                + " finding"
                + ("s" if count != 1 else "")
                + "</span>"
                + "</summary>"
                + '<div style="padding:.25rem .5rem">'
                + inner
                + "</div></details>"
            )
        killchain_html = (
            '<h4 class="forensics-section-title">Kill-Chain Breakdown</h4>'
            + "".join(tactic_rows)
        )
    else:
        killchain_html = (
            '<h4 class="forensics-section-title">Kill-Chain Breakdown</h4>'
            '<div class="forensics-empty">No MITRE tactics mapped in this window.</div>'
        )

    # ── Panel C: Affected Product Matrix ──────────────────────────────────────────────
    product_map: dict = {}
    for card in cards:
        prods = card.get("enrichment", {}).get("products", [])
        rs = card.get("risk_score", 0)
        for prod in prods:
            pm = product_map.setdefault(prod, {"count": 0, "max_score": 0})
            pm["count"] += 1
            if rs > pm["max_score"]:
                pm["max_score"] = rs

    if product_map:
        prod_rows = []
        for prod, data in sorted(
            product_map.items(),
            key=lambda x: (x[1]["max_score"], x[1]["count"]),
            reverse=True,
        )[:20]:
            sc = data["max_score"]
            sc_col = (
                "#d62828"
                if sc >= 80
                else "#f77f00" if sc >= 60 else "#f9c74f" if sc >= 30 else "#8b949e"
            )
            prod_rows.append(
                '<tr><td style="color:#e6edf3;font-size:.78rem">'
                + html.escape(prod)
                + "</td>"
                + '<td style="text-align:center">'
                + str(data["count"])
                + "</td>"
                + '<td><span style="color:'
                + sc_col
                + ';font-weight:700">'
                + str(sc)
                + "</span></td></tr>"
            )
        product_html = (
            '<h4 class="forensics-section-title">Affected Products</h4>'
            '<table class="forensics-table"><thead><tr>'
            "<th>Product</th><th>Findings</th><th>Max Risk</th>"
            "</tr></thead><tbody>" + "".join(prod_rows) + "</tbody></table>"
        )
    else:
        product_html = (
            '<h4 class="forensics-section-title">Affected Products</h4>'
            '<div class="forensics-empty">No product mentions found in this window.</div>'
        )

    # ── Panel D: IOC Intelligence ─────────────────────────────────────────────────────
    # Collect all IOC observations from this window's cards.
    # Raw indicator values (IPs, hashes, registry keys) are keyed in ioc_ledger.json
    # only and are never rendered in the HTML page.  We show: IOC type, a context
    # snippet from the source article, a source article link, and a cross-run badge.
    all_iocs: list = []
    seen_ioc_keys: set = set()
    for card in cards:
        ioc_list = card.get("enrichment", {}).get("iocs", [])
        if not isinstance(ioc_list, list):
            continue
        for ioc in ioc_list:
            if not isinstance(ioc, dict) or not ioc.get("_key"):
                continue
            key = ioc["_key"]
            if key in seen_ioc_keys:
                continue
            seen_ioc_keys.add(key)
            rc = ioc_ledger.get(key, {}).get("run_count", 1)
            all_iocs.append({**ioc, "_run_count": rc})

    # Persistent IOCs (seen in multiple runs) appear first
    all_iocs.sort(key=lambda x: x.get("_run_count", 1), reverse=True)

    if all_iocs:
        ioc_rows: list = []
        for ioc in all_iocs[:20]:
            rc = ioc.get("_run_count", 1)
            persist_badge = (
                '<span style="background:#f77f00;color:#000;font-size:.63rem;'
                'padding:.05rem .3rem;border-radius:8px;margin-left:.3rem">'
                + str(rc)
                + "\u00d7</span>"
                if rc > 1
                else ""
            )
            type_label = html.escape(ioc.get("ioc_type", "IOC"))
            snippet = ioc.get("context_snippet", "")
            snippet_html = (
                "\u201c" + html.escape(snippet[:140]) + "\u2026\u201d"
                if len(snippet) > 140
                else ("\u201c" + html.escape(snippet) + "\u201d" if snippet else "")
            )
            src_url = ioc.get("source_url", "")
            src_title = ioc.get("source_title", "Source article")[:60]
            src_cell = (
                '<a href="'
                + html.escape(src_url)
                + '" target="_blank" rel="noopener noreferrer"'
                + ' style="color:#58a6ff;font-size:.72rem">'
                + html.escape(src_title)
                + " \u2197</a>"
                if src_url
                else '<span style="color:#8b949e;font-size:.72rem">'
                + html.escape(src_title)
                + "</span>"
            )
            ioc_rows.append(
                "<tr>"
                + '<td style="white-space:nowrap;vertical-align:top;padding-top:.35rem">'
                + '<span style="color:#8b949e;font-size:.68rem;text-transform:uppercase;'
                + 'letter-spacing:.04em">'
                + type_label
                + "</span>"
                + persist_badge
                + "</td>"
                + '<td style="font-size:.74rem;color:#c9d1d9;font-style:italic;padding:0 .4rem">'
                + snippet_html
                + "</td>"
                + '<td style="vertical-align:top;padding-top:.3rem">'
                + src_cell
                + "</td>"
                + "</tr>"
            )
        ioc_html = (
            '<h4 class="forensics-section-title">IOC Intelligence</h4>'
            '<p class="forensics-hint">Indicators observed in source articles. '
            "Raw values are stored internally only \u2014 click the source link to read the original advisory.</p>"
            '<table class="forensics-table"><thead><tr>'
            "<th>Type</th><th>Context</th><th>Source</th>"
            "</tr></thead><tbody>" + "".join(ioc_rows) + "</tbody></table>"
        )
    else:
        ioc_html = (
            '<h4 class="forensics-section-title">IOC Intelligence</h4>'
            '<div class="forensics-empty">No network IOCs extracted from this window\u2019s articles.</div>'
        )

    return cve_html + killchain_html + product_html + ioc_html


def _build_priority_actions_html(cards: list) -> str:
    """Deduplicate recommended_actions_24h across P1/P2 cards; render top actions panel."""
    from collections import Counter

    action_counter: Counter = Counter()
    action_display: dict = {}  # normalised key -> best display text

    for c in cards:
        if _derive_priority(c) not in ("P1", "P2"):
            continue
        for action in c.get("recommended_actions_24h", [])[:4]:
            text = str(action).strip()
            if not text:
                continue
            key = text[:40].lower()
            action_counter[key] += 1
            if key not in action_display:
                action_display[key] = text

    if not action_counter:
        return ""

    items_html = ""
    for i, (key, count) in enumerate(action_counter.most_common(7), 1):
        text = html.escape(action_display[key])
        count_chip = (
            f'<span class="pa-count">{count}\u00d7</span>' if count >= 2 else ""
        )
        items_html += (
            f'<li class="pa-item">'
            f'<span class="pa-num">{i}</span>'
            f'<span class="pa-text">{text}</span>'
            f"{count_chip}"
            f"</li>"
        )

    return (
        f'<section class="pa-panel">'
        f'<div class="pa-title">Priority Actions \u2014 Next 24h</div>'
        f'<ol class="pa-list">{items_html}</ol>'
        f"</section>"
    )


def _build_alerts_html(cards: list, delta: dict | None) -> str:
    """Build the three-panel Alerts rail section from render-time card data."""
    delta = delta or {}
    elevated_cards = delta.get("elevated", [])

    if not cards and not elevated_cards:
        return '<div class="alert-empty">No findings available.</div>'

    # Panel 1: cards seen in 3+ consecutive runs
    persistent = sorted(
        [c for c in cards if int(c.get("run_count", 1)) >= 3],
        key=lambda c: int(c.get("run_count", 1)),
        reverse=True,
    )

    # Panel 2: cards whose risk score rose ≥10 since last run
    elevated = sorted(
        elevated_cards,
        key=lambda c: int(c.get("_score_delta", 0)),
        reverse=True,
    )

    # Panel 3: P1 priority or attribution-flagged cards, deduped by id
    p1_attr: list = []
    seen_ids: set = set()
    for c in sorted(cards, key=lambda x: int(x.get("risk_score", 0)), reverse=True):
        if _derive_priority(c) == "P1" or c.get("attribution_flag"):
            cid = c.get("id", "")
            if cid not in seen_ids:
                seen_ids.add(cid)
                p1_attr.append(c)

    def _row(c: dict, annot_html: str) -> str:
        cid = html.escape(c.get("id", ""))
        bg, fg = _heatmap_cell_color(int(c.get("risk_score", 0)), 1)
        score = int(c.get("risk_score", 0))
        title = html.escape(c.get("title", "")[:72])
        return (
            f'<div class="alert-row" data-card-id="{cid}" role="button" tabindex="0">'
            f'<span class="alert-score" style="background:{bg};color:{fg}">{score}</span>'
            f'<span class="alert-title">{title}</span>'
            f"{annot_html}"
            f"</div>"
        )

    def _section(label: str, rows_html: str, count: int) -> str:
        cnt_badge = f'<span class="alerts-cnt">{count}</span>'
        return f'<div class="alerts-subhdr">{label}{cnt_badge}</div>{rows_html}'

    persist_rows = "".join(
        _row(c, f'<span class="alert-annot alert-annot--persist">Seen {int(c.get("run_count", 1))} runs</span>')
        for c in persistent
    )

    elevated_rows = "".join(
        _row(c, f'<span class="alert-annot alert-annot--elevated">+{int(c.get("_score_delta", 0))} ↑</span>')
        for c in elevated
    )

    def _p1_annot(c: dict) -> str:
        is_p1 = _derive_priority(c) == "P1"
        is_attr = bool(c.get("attribution_flag"))
        parts = []
        if is_p1:
            parts.append('<span class="alert-annot alert-annot--p1">P1</span>')
        if is_attr:
            parts.append('<span class="alert-annot alert-annot--attr">⚠ Attr</span>')
        return "".join(parts)

    p1_rows = "".join(_row(c, _p1_annot(c)) for c in p1_attr)

    # Collapse Persistent + Elevated into a single quiet line when both are empty
    if persist_rows or elevated_rows:
        watch_section = (
            (_section("Persistent", persist_rows, len(persistent)) if persist_rows else "")
            + (_section("Elevated", elevated_rows, len(elevated)) if elevated_rows else "")
        )
    else:
        watch_section = '<div class="alert-empty">No persistent or elevated alerts this run</div>'

    return watch_section + _section("P1 / Attribution", p1_rows, len(p1_attr))


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
    feed_health: dict = None,
    run_metrics: dict = None,
    feed_run_metrics: dict = None,
    velocity: dict = None,
    ioc_ledger: dict = None,
):
    # KPI stats
    total_findings = len(cards)
    p1_count = sum(1 for c in cards if _derive_priority(c) == "P1")
    exploited_count = sum(1 for c in cards if _is_exploitish(c))
    hp_count = sum(1 for c in cards if c.get("matched_targets"))
    control_plane_count = sum(
        1
        for c in cards
        if any(
            d in c.get("domains", []) for d in ("cloud_iam", "identity", "supply_chain")
        )
    )
    top_domain_key = (
        max(
            heatmap.keys(),
            key=lambda k: (heatmap[k].get("max_score", 0), heatmap[k].get("count", 0)),
        )
        if heatmap
        else "uncategorised"
    )
    top_domain_label = heatmap.get(top_domain_key, {}).get("label", "Other")

    trend_txt = "—"
    if history and len(history) >= 2:
        a = history[-2]["counts"]["clusters"]
        b = history[-1]["counts"]["clusters"]
        _trend_delta = b - a
        trend_txt = f"{_trend_delta:+d}"

    p1_delta_html = ""
    exp_delta_html = ""
    if delta:
        _p1_new = sum(1 for c in delta.get("new", []) if _derive_priority(c) == "P1")
        _p1_res = sum(1 for c in delta.get("resolved", []) if _derive_priority(c) == "P1")
        _p1_net = _p1_new - _p1_res
        if _p1_net > 0:
            p1_delta_html = f'<span class="kpi-delta kpi-delta--up">+{_p1_net} ↑</span>'
        elif _p1_net < 0:
            p1_delta_html = f'<span class="kpi-delta kpi-delta--down">{_p1_net} ↓</span>'
        _exp_new = sum(1 for c in delta.get("new", []) if _is_exploitish(c))
        _exp_res = sum(1 for c in delta.get("resolved", []) if _is_exploitish(c))
        _exp_net = _exp_new - _exp_res
        if _exp_net > 0:
            exp_delta_html = f'<span class="kpi-delta kpi-delta--up">+{_exp_net} ↑</span>'
        elif _exp_net < 0:
            exp_delta_html = f'<span class="kpi-delta kpi-delta--down">{_exp_net} ↓</span>'

    kpi_html = f"""
        <section class="kpi-grid">
            <div class="kpi"><span class="k">Findings</span><span class="v">{total_findings}</span></div>
            <div class="kpi"><span class="k">P1</span><span class="v">{p1_count}</span>{p1_delta_html}</div>
            <div class="kpi"><span class="k">Exploited</span><span class="v">{exploited_count}</span>{exp_delta_html}</div>
            <div class="kpi"><span class="k">High-Profile</span><span class="v">{hp_count}</span></div>
            <div class="kpi"><span class="k">Control Plane</span><span class="v">{control_plane_count}</span></div>
            <div class="kpi"><span class="k">Top Domain</span><span class="v v-sm">{html.escape(top_domain_label)}</span></div>
        </section>
        """

    # Feed contribution from cited source links (includes newly added feeds as domains appear)
    feed_rollup: dict = {}
    for c in cards:
        rs = int(c.get("risk_score", 0))
        for s in c.get("sources", {}).get("primary", []):
            dom = tldextract.extract(s.get("url", "")).registered_domain or "unknown"
            cur = feed_rollup.setdefault(dom, {"count": 0, "max_score": 0})
            cur["count"] += 1
            cur["max_score"] = max(cur["max_score"], rs)
    top_feeds = sorted(
        feed_rollup.items(),
        key=lambda kv: (kv[1]["count"], kv[1]["max_score"]),
        reverse=True,
    )[:10]
    feed_rows = "".join(
        f"<tr><td>{html.escape(dom)}</td><td>{vals['count']}</td><td>{vals['max_score']}</td></tr>"
        for dom, vals in top_feeds
    )

    # --- Run metrics bar and per-feed health table ---
    _fh = feed_health or {}
    _rm = run_metrics or {}
    _frm = feed_run_metrics or {}
    _rm_elapsed = _rm.get("elapsed_s", "—")
    _rm_ok = _rm.get("feeds_ok", "—")
    _rm_total = _rm.get("feeds_total", "—")
    _rm_fail = _rm.get("feeds_fail", "—")
    _rm_groq = _rm.get("groq_status", "—")
    _rm_items = _rm.get("items_polled", "—")
    _rm_window = _rm.get("window_h", "—")
    run_metrics_html = (
        (
            f'<div class="run-metrics-bar">'
            f'<span class="rm-chip">⏱ {_rm_elapsed}s</span>'
            f'<span class="rm-chip rm-ok">✓ {_rm_ok}/{_rm_total} feeds</span>'
            f'<span class="rm-chip rm-fail">✗ {_rm_fail} failed</span>'
            f'<span class="rm-chip">📡 {_rm_items} items</span>'
            f'<span class="rm-chip">🕐 {_rm_window}h window</span>'
            f'<span class="rm-chip">AI: {_rm_groq}</span>'
            f"</div>"
        )
        if _rm
        else ""
    )
    health_rows = ""
    for fid, fmeta in sorted(_frm.items()):
        hist = _fh.get(fid, {})
        total_calls = max(hist.get("total_calls", 1), 1)
        total_ok = hist.get("total_ok", 0)
        reliability = round(total_ok / total_calls * 100)
        consec_fail = hist.get("consecutive_fail", 0)
        status_dot = "🔴" if consec_fail >= 3 else "🟡" if consec_fail >= 1 else "🟢"
        health_rows += (
            f"<tr>"
            f"<td>{status_dot} {html.escape(fid)}</td>"
            f"<td>{fmeta.get('count', 0)}</td>"
            f"<td>{reliability}%</td>"
            f"<td>{fmeta.get('elapsed_ms', 0)}ms</td>"
            f"</tr>"
        )

    threat_svg = _build_threat_map_svg(cards, heatmap, velocity=velocity)
    domain_rank_html = _build_domain_rank_html(cards, heatmap, velocity=velocity)

    _today_et = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%d")
    history_section = _build_history_accordion(history_days or [], today_str=_today_et)

    # --- Delta strip ---
    delta_strip_html = ""
    resolved_drawer_html = ""
    if delta is not None:
        n_new = len(delta.get("new", []))
        n_elev = len(delta.get("elevated", []))
        n_res = len(delta.get("resolved", []))
        if n_new == 0 and n_elev == 0 and n_res == 0:
            delta_strip_html = (
                '<div class="delta-strip">'
                '<span class="delta-chip delta-chip--quiet">No changes from previous run</span>'
                "</div>"
            )
        else:
            chips = []
            if n_new:
                chips.append(
                    f'<span class="delta-chip delta-chip--new">+{n_new}&nbsp;New</span>'
                )
            if n_elev:
                chips.append(
                    f'<span class="delta-chip delta-chip--elevated">{n_elev}&nbsp;Elevated</span>'
                )
            if n_res:
                chips.append(
                    f'<span class="delta-chip delta-chip--resolved">{n_res}&nbsp;Resolved</span>'
                )
            delta_strip_html = f'<div class="delta-strip">{"  ".join(chips)}</div>'
        if delta.get("resolved"):
            res_rows = "".join(
                f'<tr><td>{html.escape(c.get("title", "")[:90])}</td>'
                f'<td style="text-align:right;padding-right:.6rem">{int(c.get("risk_score", 0))}</td></tr>'
                for c in delta["resolved"]
            )
            resolved_drawer_html = (
                f'<details class="resolved-drawer">'
                f"<summary>{n_res} resolved since previous run</summary>"
                f'<table><thead><tr><th>Finding</th><th style="text-align:right">Prev&nbsp;risk</th></tr></thead>'
                f"<tbody>{res_rows}</tbody></table></details>"
            )

    # --- High-profile target panel (only rendered when matches exist) ---
    hp_panel_html = ""
    if hp_count:
        # Collect all matched targets across cards, count occurrences, sort by count desc
        from collections import Counter

        target_counter: Counter = Counter()
        for c in cards:
            for t in c.get("matched_targets", []):
                target_counter[t] += 1
        chips_html = "".join(
            f'<span class="hp-chip">{html.escape(name)}'
            f'<span class="hp-chip-count">{cnt}</span></span>'
            for name, cnt in target_counter.most_common()
        )
        hp_panel_html = (
            f'<section class="hp-panel">'
            f'<div class="hp-panel-title">High-Profile Targets in This Window</div>'
            f'<div class="hp-chip-list">{chips_html}</div>'
            f"</section>"
        )

    def _card_tier(c: dict) -> str:
        """Classify a card into a persistence tier for display grouping."""
        if c.get("shelf_resolved"):
            return "resolved"
        run_count = c.get("run_count", 1)
        shelf_days = c.get("shelf_days", 0)
        if run_count > 5 or (shelf_days > 7 and not c.get("shelf_resolved")):
            return "persistent"
        if run_count >= 2:
            return "evolving"
        return "new"

    _TIER_META = {
        "persistent": ("Persistent / Unpatched", "tier-persistent",
                       "Active for more than 5 runs or 7+ days without a fix."),
        "new":        ("New This Run",           "tier-new",
                       "Findings appearing for the first time."),
        "evolving":   ("Evolving",               "tier-evolving",
                       "Seen across multiple runs — monitor for patch or escalation."),
        "resolved":   ("Resolved",               "tier-resolved",
                       "Patch confirmed this run."),
    }
    _TIER_ORDER = ["persistent", "new", "evolving", "resolved"]

    # Accumulate rendered card HTML per tier (preserves risk-score sort from cards list)
    _tier_html: dict = {t: "" for t in _TIER_ORDER}

    rows = ""
    for c in cards:
        links = "".join(
            f'<li><a href="{html.escape(s["url"])}" target="_blank" rel="noopener noreferrer">{html.escape(s["title"])}</a></li>'
            for s in c["sources"]["primary"]
        )
        badge_bg, badge_fg = _heatmap_cell_color(c["risk_score"], 1)
        pri = _derive_priority(c)
        pri_cls = "p1" if pri == "P1" else "p2" if pri == "P2" else "p3"
        conf = c.get("confidence", None)
        conf_txt = (
            f'<span class="confidence">confidence {float(conf):.2f}</span>'
            if isinstance(conf, (int, float))
            else ""
        )
        tags = " ".join(
            f'<span class="domain-tag">{html.escape(_TAXONOMY.get(d, {}).get("label", d))}</span>'
            for d in c.get("domains", [])
            if d != "uncategorised"
        )
        actions24 = c.get("recommended_actions_24h", [])[:4]
        actions7 = c.get("recommended_actions_7d", [])[:4]
        act24_html = "".join(f"<li>{html.escape(str(a))}</li>" for a in actions24)
        act7_html = "".join(f"<li>{html.escape(str(a))}</li>" for a in actions7)
        domains_attr = " ".join(c.get("domains", []))
        why_now = html.escape(c.get("why_now", ""))
        _ps = c.get("patch_status", "unknown")
        patch_badge_html = (
            f'<span class="patch-badge patch-badge--fixed">Patch Available</span>'
            if _ps == "patched"
            else (
                f'<span class="patch-badge patch-badge--workaround">Workaround</span>'
                if _ps == "workaround"
                else (
                    f'<span class="patch-badge patch-badge--no-fix">No Fix · Exploited</span>'
                    if _ps == "no_fix"
                    else ""
                )
            )
        )
        _hp_targets = c.get("matched_targets", [])
        hp_badge_html = (
            f'<span class="hp-badge" title="{html.escape(", ".join(_hp_targets[:5]))}">High-Profile</span>'
            if _hp_targets
            else ""
        )
        _cve_list = _extract_cves(c.get("title", "") + " " + c.get("summary", ""))
        cve_badge_html = (
            f'<span class="cve-badge">{len(_cve_list)} CVE{"s" if len(_cve_list) != 1 else ""}</span>'
            if _cve_list
            else ""
        )
        _tactic = c.get("tactic_name", "")
        tactic_chip_html = (
            f'<span class="tactic-chip">{html.escape(_tactic)}</span>'
            if _tactic
            else ""
        )
        _shelf_days = int(c.get("shelf_days", 0))
        _run_count = int(c.get("run_count", 1))
        _shelf_resolved = c.get("shelf_resolved", False)
        if _shelf_days >= 1 and _shelf_resolved:
            shelf_badge_html = (
                f'<span class="shelf-badge shelf-badge--resolved" title="Patch available — first seen {_shelf_days}d ago &middot; seen {_run_count} runs">'
                f"{_shelf_days}d (resolved)</span>"
            )
        elif _shelf_days >= 1:
            shelf_badge_html = (
                f'<span class="shelf-badge" title="First seen {_shelf_days}d ago &middot; seen {_run_count} runs">'
                f"{_shelf_days}d</span>"
            )
        else:
            shelf_badge_html = ""
        attr_badge_html = (
            '<span class="attr-badge" title="This finding contains nation-state attribution '
            "sourced from a news article. Attribution is unverified and should be "
            'treated with appropriate scrutiny.">\u26a0 Attribution Unverified</span>'
            if c.get("attribution_flag")
            else ""
        )
        kev_badge_html = (
            '<span class="kev-badge" title="CVE confirmed in CISA Known Exploited Vulnerabilities catalog — active in-the-wild exploitation">CISA KEV</span>'
            if c.get("is_kev")
            else ""
        )
        _corr = int(c.get("corroboration_count", 1))
        corr_badge_html = (
            f'<span class="corr-badge" title="{_corr} independent sources cover this finding">{_corr} sources</span>'
            if _corr >= 2
            else ""
        )
        _epss = c.get("epss_score")
        epss_badge_html = (
            f'<span class="epss-badge" title="EPSS exploitation probability: {_epss:.1%} — high likelihood of active exploitation">EPSS {_epss:.0%}</span>'
            if isinstance(_epss, float) and _epss >= 0.4
            else ""
        )
        _has_authoritative = bool(c.get("is_kev")) or bool(cve_badge_html)
        _prim_sources = c.get("sources", {}).get("primary", [])
        if not _has_authoritative and _prim_sources:
            _src_domain = tldextract.extract(_prim_sources[0].get("url", "")).registered_domain
            src_chip_html = (
                f'<span class="src-chip" title="News source — not CVE/KEV backed">via {html.escape(_src_domain)}</span>'
                if _src_domain else ""
            )
        else:
            src_chip_html = ""
        rows += f"""
                <details class="cluster" id="card-{html.escape(c.get('id', ''))}" data-domains="{html.escape(domains_attr)}" data-tactic="{html.escape(_tactic)}">
                    <summary>
                        <span class="badge" style="background:{badge_bg};color:{badge_fg}">{c['risk_score']}</span>
                        <span class="priority {pri_cls}">{pri}</span>
                        {kev_badge_html}
                        {epss_badge_html}
                        {patch_badge_html}
                        {hp_badge_html}
                        {cve_badge_html}
                        {corr_badge_html}
                        {src_chip_html}
                        {tactic_chip_html}
                        {shelf_badge_html}
                        {attr_badge_html}
                        {html.escape(c['title'])}
                        <div class="domain-tags" style="margin:0 0 0 .5rem;display:inline">{tags}</div>
                    </summary>
                    <div class="cluster-body">
                        <p>{html.escape(c['summary'])}</p>
                        {f'<p class="why-now"><strong>Why now:</strong> {why_now}</p>' if why_now else ''}
                        {conf_txt}
                        {f'<div class="actions"><div><strong>Next 24h</strong><ul>{act24_html}</ul></div><div><strong>Next 7d</strong><ul>{act7_html}</ul></div></div>' if (act24_html or act7_html) else ''}
                        {_build_enrichment_html(c.get('enrichment'))}
                        <ul>{links}</ul>
                    </div>
                </details>"""
        _tier_html[_card_tier(c)] += rows
        rows = ""

    # Assemble tiers with headers; empty tiers are skipped
    for _tier_key in _TIER_ORDER:
        _content = _tier_html[_tier_key]
        if not _content:
            continue
        _label, _cls, _hint = _TIER_META[_tier_key]
        _count = _content.count('class="cluster ')
        rows += (
            f'<div class="tier-header {_cls}">'
            f'<span class="tier-label">{_label}</span>'
            f'<span class="tier-count">{_count}</span>'
            f'<span class="tier-hint">{_hint}</span>'
            f"</div>"
            + _content
        )

    # Holistic stress matrix (adjacency feel): domain x indicator intensity
    indicator_defs = [
        ("volume", "Volume"),
        ("severity", "Severity"),
        ("urgency", "Urgency"),
        ("exploit", "Exploit"),
        ("confidence", "Confidence"),
    ]
    domain_order = [k for k in _TAXONOMY.keys() if k != "uncategorised"]
    if "uncategorised" in _TAXONOMY:
        domain_order.append("uncategorised")

    domain_stats = {}
    for dk in domain_order:
        subset = [c for c in cards if dk in c.get("domains", [])]
        count = len(subset)
        max_risk = max((int(c.get("risk_score", 0)) for c in subset), default=0)
        p1 = sum(1 for c in subset if _derive_priority(c) == "P1")
        exploit = sum(1 for c in subset if _is_exploitish(c))
        conf_vals = [
            float(c.get("confidence"))
            for c in subset
            if isinstance(c.get("confidence", None), (int, float))
        ]
        avg_conf = (sum(conf_vals) / len(conf_vals)) if conf_vals else 0.0
        domain_stats[dk] = {
            "count": count,
            "max_risk": max_risk,
            "p1_ratio": (p1 / count) if count else 0.0,
            "exploit_ratio": (exploit / count) if count else 0.0,
            "avg_conf": avg_conf,
        }

    max_count = max((v["count"] for v in domain_stats.values()), default=0)

    def _indicator_val(dk: str, ik: str) -> int:
        ds = domain_stats.get(dk, {})
        if ik == "volume":
            return int(
                round(((ds.get("count", 0) / max_count) if max_count else 0.0) * 100)
            )
        if ik == "severity":
            return int(ds.get("max_risk", 0))
        if ik == "urgency":
            return int(round(ds.get("p1_ratio", 0.0) * 100))
        if ik == "exploit":
            return int(round(ds.get("exploit_ratio", 0.0) * 100))
        if ik == "confidence":
            return int(round(ds.get("avg_conf", 0.0) * 100))
        return 0

    matrix_head = "".join(f"<th>{lbl}</th>" for _, lbl in indicator_defs)
    matrix_rows = ""
    for dk in domain_order:
        dlabel = _TAXONOMY.get(dk, {}).get("label", dk)
        tds = ""
        for ik, ilabel in indicator_defs:
            val = max(0, min(100, _indicator_val(dk, ik)))
            alpha = 0.06 + (0.72 * (val / 100.0))
            glow = 2 + int((val / 100.0) * 14)
            tds += (
                f'<td class="mx-cell" style="background:rgba(31,111,235,{alpha:.3f});box-shadow:inset 0 0 {glow}px rgba(88,166,255,.35)" '
                f'title="{html.escape(dlabel)} · {ilabel}: {val}">'
                f'<span class="mx-dot" style="opacity:{0.2 + (val/100.0)*0.8:.3f}"></span>'
                f'<span class="mx-count">{val}</span>'
                f"</td>"
            )
        matrix_rows += f'<tr><th class="mx-row">{html.escape(dlabel)}</th>{tds}</tr>'

    matrix_section = f"""
        <section class="panel matrix-panel">
            <h3 style="margin:.1rem 0 .5rem">Holistic Domain Matrix</h3>
            <div class="muted" style="margin:0 0 .55rem">Uniform adjacency-style grid. Cell intensity tracks domain indicators.</div>
            <table class="risk-matrix">
                <thead><tr><th>Domain</th>{matrix_head}</tr></thead>
                <tbody>{matrix_rows}</tbody>
            </table>
        </section>
    """

    # --- MITRE tactic filter strip ---
    _MITRE_TACTICS = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command & Control",
        "Exfiltration",
        "Impact",
    ]
    active_tactics = {c.get("tactic_name", "") for c in cards if c.get("tactic_name")}
    covered_count = len(active_tactics)
    total_tactics = len(_MITRE_TACTICS)
    coverage_pct = round(covered_count / total_tactics * 100) if total_tactics else 0
    # Coverage bar: 14 pips, filled = tactic present in this window's findings
    pip_html = "".join(
        f'<span class="tactic-pip tactic-pip--{"filled" if t in active_tactics else "hollow"}" '
        f'title="{html.escape(t)}"></span>'
        for t in _MITRE_TACTICS
    )
    coverage_bar_html = (
        f'<div class="tactic-coverage" id="tactic-coverage">'
        f'<span class="tactic-coverage-label">{covered_count} / {total_tactics} tactics covered</span>'
        f'<span class="tactic-coverage-bar">{pip_html}</span>'
        f'<span class="tactic-coverage-pct">{coverage_pct}%</span>'
        f"</div>"
        if active_tactics
        else ""
    )
    tactic_buttons = "".join(
        f'<button class="tactic-btn{" tactic-btn--active" if t in active_tactics else ""}" '
        f'data-tactic="{html.escape(t)}" type="button">{html.escape(t)}</button>'
        for t in _MITRE_TACTICS
    )
    tactic_strip_html = (
        (
            f"{coverage_bar_html}"
            f'<div class="tactic-strip" id="tactic-strip">'
            f'<button class="tactic-btn tactic-btn--all tactic-btn--active" data-tactic="all" type="button">All Tactics</button>'
            f"{tactic_buttons}"
            f"</div>"
        )
        if active_tactics
        else ""
    )

    card_data = []
    for c in cards:
        prim = c.get("sources", {}).get("primary", [])
        sources_brief = [
            {"title": s.get("title", "")[:80], "url": s.get("url", "")}
            for s in prim[:3]
            if isinstance(s, dict) and s.get("url")
        ]
        card_data.append(
            {
                "id": c.get("id", ""),
                "title": c.get("title", ""),
                "risk_score": int(c.get("risk_score", 0)),
                "priority": _derive_priority(c),
                "domains": c.get("domains", []),
                "summary": c.get("summary", ""),
                "sources": sources_brief,
                "tactic": c.get("tactic_name", ""),
                "shelf_days": int(c.get("shelf_days", 0)),
                "run_count": int(c.get("run_count", 1)),
                "first_seen_ts": c.get("first_seen_ts", ""),
                "actions_24h": c.get("recommended_actions_24h", [])[:4],
                "patch_status": c.get("patch_status", "unknown"),
                "shelf_resolved": bool(c.get("shelf_resolved", False)),
                "cves": list((c.get("enrichment") or {}).get("cves") or []),
            }
        )

    forensics_html = _build_forensics_html(cards, ioc_ledger or {})
    alerts_html = _build_alerts_html(cards, delta)
    priority_actions_html = _build_priority_actions_html(cards)

    try:
        _ts_dt = datetime.strptime(ts, "%Y-%m-%d_%H-%M").replace(tzinfo=timezone.utc)
        _cutoff_dt = _ts_dt - timedelta(hours=since_hours)
        _window_chip = f"Since {_cutoff_dt.strftime('%b %d, %H:%M')} UTC"
    except Exception:
        _window_chip = f"Last {since_hours}h"

    page_html = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Watchtower — InfraSec Briefing</title>
<style>
:root{{--rail-width-expanded:360px;--rail-width-collapsed:64px;--rail-width:var(--rail-width-expanded);--rail-min-width:320px;--rail-max-width:480px;--rail-gap:8px;--page-gutter:16px}}
*{{box-sizing:border-box}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:#0a0a0a}}
::-webkit-scrollbar-thumb{{background:#2a2a2a;border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:#3a3a3a}}
*{{scrollbar-width:thin;scrollbar-color:#2a2a2a #0a0a0a}}
body{{font-family:system-ui,sans-serif;margin:0;padding:0;background:#0f0f0f;color:#c9d1d9}}
.page-wrap{{max-width:1320px;margin:0 auto;position:relative}}
.app-shell{{position:relative;padding-top:88px}}
.app-main{{padding:0 var(--page-gutter) 1.4rem;padding-right:calc(var(--rail-width) + var(--rail-gap) + var(--page-gutter));transition:padding-right .2s ease}}
body.rail-collapsed .app-main{{padding-right:calc(var(--rail-width-collapsed) + var(--rail-gap) + var(--page-gutter))}}
.header-bar{{position:fixed;top:0;left:0;right:0;background:#0f0f0f;border-bottom:1px solid #2a2a2a;z-index:20;padding:.8rem var(--page-gutter);box-shadow:0 2px 8px rgba(0,0,0,.2)}}
.header-content{{max-width:1320px;margin:0 auto;padding-right:calc(var(--rail-width) + var(--rail-gap))}}
body.rail-collapsed .header-content{{padding-right:calc(var(--rail-width-collapsed) + var(--rail-gap))}}
.header-bar h1{{margin:0;padding:0;border:none;font-size:1.35rem}}
.header-bar p{{margin:.25rem 0 0;font-size:.82rem;color:#8b949e}}
h1{{border-bottom:2px solid #333;padding-bottom:.4rem;color:#e6edf3}}
h2{{color:#e6edf3}}
a{{color:#999}}
p{{color:#c9d1d9}}
.kpi-grid{{display:grid;grid-template-columns:repeat(7,minmax(110px,1fr));gap:8px;margin:1rem 0 1.2rem}}
.kpi{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.55rem .7rem;display:flex;flex-direction:column;gap:.2rem}}
.kpi .k{{font-size:.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700}}
.kpi .v{{font-size:1.2rem;color:#e6edf3;font-weight:800}}
.kpi .v-sm{{font-size:.95rem}}
.kpi-delta{{font-size:.62rem;font-weight:700;letter-spacing:.02em;margin-top:.1rem}}
.kpi-delta--up{{color:#f85149}}
.kpi-delta--down{{color:#3fb950}}
.hm-cell{{border-radius:6px;padding:.7rem .55rem;text-align:center;border:1px solid rgba(255,255,255,.08);cursor:pointer;font-family:inherit}}
.hm-cell.active{{outline:2px solid #666;outline-offset:1px}}
.hm-label{{display:block;font-size:.72rem;font-weight:700;margin:.15rem 0}} 
.hm-meta{{display:block;font-size:.66rem;opacity:.85}}
.hm-score{{display:block;font-size:1.15rem;font-weight:800;margin-top:.2rem}}
.panel{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.7rem .8rem}}
.panel h3{{margin:.2rem 0 .5rem;font-size:.92rem;color:#e6edf3}}
.panel .muted{{color:#8b949e;font-size:.8rem}}
.feed-table{{width:100%;border-collapse:collapse;font-size:.78rem}}
.feed-table th,.feed-table td{{border-bottom:1px solid #333;padding:.3rem .2rem;text-align:left}}
.matrix-panel{{margin:.2rem 0 1rem}}
.risk-matrix{{width:100%;border-collapse:separate;border-spacing:4px;table-layout:fixed}}
.risk-matrix th{{font-size:.68rem;color:#8b949e;font-weight:700;text-align:center;letter-spacing:.02em}}
.risk-matrix .mx-row{{text-align:left;padding-left:.3rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px}}
.mx-cell{{height:44px;border:1px solid #333;border-radius:6px;position:relative;text-align:center;vertical-align:middle;overflow:hidden;transition:filter .12s ease,transform .12s ease}}
.mx-cell:hover{{filter:brightness(1.1);transform:translateY(-1px)}}
.mx-dot{{position:absolute;left:50%;top:50%;width:20px;height:20px;border-radius:999px;transform:translate(-50%,-50%);background:radial-gradient(circle,rgba(180,180,180,.75) 0%, rgba(180,180,180,.05) 70%)}}
.mx-count{{position:relative;display:block;font-size:.82rem;font-weight:800;color:#e6edf3;line-height:1}}
.tier-header{{display:flex;align-items:center;gap:.55rem;margin:1.1rem 0 .35rem;padding:.3rem 0 .3rem;border-bottom:1px solid #2a2a2a}}
.tier-label{{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em}}
.tier-count{{font-size:.7rem;font-weight:700;padding:1px 7px;border-radius:999px;border:1px solid currentColor;opacity:.85}}
.tier-hint{{font-size:.68rem;color:#6a7f98;font-style:italic;margin-left:.2rem}}
.tier-persistent .tier-label{{color:#f85149}}.tier-persistent .tier-count{{color:#f85149}}
.tier-new .tier-label{{color:#e6edf3}}.tier-new .tier-count{{color:#e6edf3}}
.tier-evolving .tier-label{{color:#d29922}}.tier-evolving .tier-count{{color:#d29922}}
.tier-resolved .tier-label{{color:#3fb950}}.tier-resolved .tier-count{{color:#3fb950}}
.cluster{{background:rgba(255,255,255,0.01);border:1px solid #2a2a2a;border-radius:6px;padding:0;margin:.55rem 0;overflow:hidden}}
.cluster summary{{list-style:none;padding:.62rem .85rem;cursor:pointer;display:flex;align-items:center;gap:.35rem;user-select:none;color:#c9d1d9;font-size:.92rem}}
.cluster summary::-webkit-details-marker{{display:none}}
.cluster summary::before{{content:"–";font-size:.75rem;transition:transform .15s;flex-shrink:0;color:#8b949e;display:inline-block;width:.7rem;text-align:center}}
.cluster[open] summary::before{{transform:none;content:"+"}}
.cluster-body{{padding:.2rem .9rem .85rem;color:#c9d1d9}}
.badge{{border-radius:999px;padding:2px 8px;font-size:.72rem;font-weight:700;margin-right:.35rem;background:rgba(255,255,255,.06)!important;color:#c9d1d9!important}}
.priority{{border-radius:999px;padding:2px 8px;font-size:.68rem;font-weight:800;letter-spacing:.02em;margin-right:.3rem;border:1px solid #333}}
.priority.p1{{background:rgba(170,28,28,.16);color:#c88888;border-color:rgba(170,28,28,.36)}}
.priority.p2{{background:rgba(100,100,100,.15);color:#aaa;border-color:rgba(100,100,100,.30)}}
.priority.p3{{background:#252525;color:#c9d1d9}}
.domain-tags{{margin:.3rem 0 .6rem}} .domain-tag{{display:inline-block;background:#252525;color:#8b949e;border:1px solid #333;border-radius:3px;font-size:.7rem;padding:1px 6px;margin:0 3px 3px 0}}
.executive{{background:#1a1a1a;border-left:3px solid #555;border-radius:4px;padding:.8rem 1.1rem;margin:1rem 0 1.8rem}}
.executive h2{{margin:0 0 .4rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;color:#999}}
.executive p{{margin:0;line-height:1.75;font-size:.95rem;color:#c9d1d9}}
.history-panel{{background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:.45rem 1rem;margin:0 0 1.2rem;display:flex;align-items:center;gap:.8rem;flex-wrap:wrap}}
.hs-label{{color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.05em;font-size:.68rem}}
.hs-val{{font-weight:700;font-size:.85rem;color:#e6edf3}}
.actions{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:.4rem 0 .7rem}}
.actions ul{{margin:.3rem 0 .2rem 1rem;padding:0}}
.confidence{{display:inline-block;font-size:.72rem;color:#8b949e;border:1px solid #333;border-radius:999px;padding:2px 8px;margin-bottom:.3rem}}
.cve-badge{{display:inline-block;font-size:.62rem;font-weight:700;background:rgba(30,100,200,.12);color:#6ea8fe;border:1px solid rgba(30,100,200,.28);border-radius:3px;padding:1px 6px;margin-left:.35rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0}}
.findings-filter{{display:flex;align-items:center;gap:.6rem;margin:.25rem 0 .6rem}}
.findings-search{{background:#151515;border:1px solid #333;border-radius:4px;color:#c9d1d9;font-size:.82rem;padding:.3rem .55rem;width:min(340px,100%);outline:none}}
.findings-search:focus{{border-color:#555;background:#1a1a1a}}
.findings-count{{font-size:.75rem;color:#8b949e}}
.run-metrics-bar{{display:flex;gap:.35rem;flex-wrap:wrap;margin:.2rem 0 .45rem;padding:.3rem 0;border-bottom:1px solid #252525}}
.rm-chip{{font-size:.68rem;padding:2px 7px;border-radius:999px;border:1px solid #333;background:#181818;color:#aaa}}
.rm-ok{{color:#3fb950;border-color:rgba(35,134,54,.35);background:rgba(35,134,54,.08)}}
.rm-fail{{color:#f85149;border-color:rgba(170,28,28,.35);background:rgba(170,28,28,.08)}}
.vel-chip{{font-size:.62rem;font-weight:800;padding:0 3px;flex-shrink:0}}
.vel-up2{{color:#f0883e}}
.vel-up1{{color:#d29922}}
.vel-dn{{color:#3fb950}}
.tactic-strip{{display:flex;flex-wrap:wrap;gap:5px;margin:.3rem 0 .55rem;padding:.45rem 0;border-bottom:1px solid #252525}}
.tactic-coverage{{display:flex;align-items:center;gap:.55rem;padding:.35rem 0 .3rem;border-top:1px solid #252525;border-bottom:1px solid #1e1e1e;margin-bottom:.3rem;flex-wrap:wrap}}
.tactic-coverage-label{{font-size:.67rem;color:#5a7090;white-space:nowrap}}
.tactic-coverage-bar{{display:flex;gap:3px;align-items:center}}
.tactic-coverage-pct{{font-size:.67rem;color:#5a7090;font-weight:700}}
.tactic-pip{{display:inline-block;width:10px;height:10px;border-radius:2px;transition:transform .1s}}
.tactic-pip--filled{{background:rgba(58,130,246,.55);border:1px solid rgba(58,130,246,.7)}}
.tactic-pip--filled:hover{{transform:scale(1.3)}}
.tactic-pip--hollow{{background:#1a1a1a;border:1px solid #2e2e2e}}
.tactic-btn{{background:#181818;border:1px solid #2a2a2a;color:#5a6a7a;font-size:.67rem;padding:2px 9px;border-radius:999px;cursor:pointer;transition:background .12s,color .12s}}
.tactic-btn:hover{{background:#252525;color:#aaa}}
.tactic-btn--active{{background:rgba(30,80,160,.18);border-color:rgba(58,130,246,.35);color:#79b8ff}}
.tactic-btn--all.tactic-btn--active{{background:rgba(50,50,50,.25);border-color:#555;color:#c9d1d9}}
.tactic-chip{{display:inline-block;font-size:.6rem;font-weight:700;background:rgba(88,130,240,.12);color:#6ea8fe;border:1px solid rgba(88,130,240,.25);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0}}
.shelf-badge{{display:inline-block;font-size:.6rem;font-weight:700;background:rgba(210,90,20,.1);color:#e8864a;border:1px solid rgba(210,90,20,.25);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0;cursor:default}}
.shelf-badge--resolved{{background:rgba(100,100,100,.1);color:#8b949e;border-color:rgba(100,100,100,.25)}}
.kev-badge{{display:inline-block;font-size:.6rem;font-weight:700;background:rgba(180,20,20,.18);color:#ff6b6b;border:1px solid rgba(180,20,20,.4);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.04em;vertical-align:middle;flex-shrink:0;cursor:default}}
.corr-badge{{display:inline-block;font-size:.6rem;font-weight:600;background:rgba(40,80,160,.1);color:#6ea8fe;border:1px solid rgba(40,80,160,.25);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0;cursor:default}}
.epss-badge{{display:inline-block;font-size:.6rem;font-weight:700;background:rgba(230,100,20,.15);color:#f4a054;border:1px solid rgba(230,100,20,.35);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.03em;vertical-align:middle;flex-shrink:0;cursor:default}}
.attr-badge{{display:inline-block;font-size:.6rem;font-weight:700;background:rgba(180,140,10,.12);color:#d4a017;border:1px solid rgba(180,140,10,.3);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0;cursor:default}}
.src-chip{{display:inline-block;font-size:.6rem;font-weight:600;background:rgba(80,80,80,.15);color:#8b949e;border:1px solid rgba(80,80,80,.3);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0;cursor:default}}
.enrich-block{{margin:.6rem 0 .2rem;border:1px solid #222;border-radius:5px;overflow:hidden}}
.enrich-summary{{font-size:.72rem;color:#5a7090;cursor:pointer;padding:.35rem .6rem;list-style:none;display:flex;align-items:center;gap:.4rem;user-select:none}}
.enrich-summary::-webkit-details-marker{{display:none}}
.enrich-summary:hover{{color:#88a0b8}}
.enrich-src-count{{font-size:.65rem;color:#3a5070;background:#141e2a;border-radius:999px;padding:0 6px}}
.enrich-body{{padding:.4rem .65rem .5rem;border-top:1px solid #1e1e1e;display:flex;flex-direction:column;gap:.3rem}}
.enrich-lede{{font-size:.75rem;color:#8899aa;margin:0 0 .2rem;line-height:1.45;font-style:italic}}
.enrich-row{{display:flex;align-items:center;flex-wrap:wrap;gap:.25rem;font-size:.68rem}}
.enrich-label{{color:#3a5070;font-size:.63rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;min-width:4rem;flex-shrink:0}}
.enrich-cve{{background:rgba(220,50,50,.1);color:#e05555;border:1px solid rgba(220,50,50,.2);border-radius:3px;padding:1px 5px;font-size:.65rem;font-weight:700}}
.enrich-cve--extra{{background:rgba(220,50,50,.05);color:#a04040;border-style:dashed}}
.enrich-product{{background:rgba(50,130,200,.1);color:#5599cc;border:1px solid rgba(50,130,200,.2);border-radius:3px;padding:1px 6px;font-size:.65rem}}
.enrich-version{{background:rgba(80,160,80,.08);color:#66aa66;border:1px solid rgba(80,160,80,.2);border-radius:3px;padding:1px 5px;font-size:.65rem;font-family:monospace}}
.enrich-date{{background:rgba(160,130,50,.08);color:#aa9955;border:1px solid rgba(160,130,50,.18);border-radius:3px;padding:1px 6px;font-size:.65rem}}
.hp-badge{{display:inline-block;font-size:.65rem;font-weight:700;letter-spacing:.04em;border-radius:3px;padding:1px 7px;margin-left:.45rem;vertical-align:middle;text-transform:uppercase;background:rgba(139,92,246,.15);color:#a78bfa;border:1px solid rgba(139,92,246,.3)}}
.hp-panel{{background:rgba(139,92,246,.06);border:1px solid rgba(139,92,246,.2);border-radius:6px;padding:.65rem 1rem .7rem;margin:.2rem 0 1rem}}
.hp-panel-title{{font-size:.75rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#a78bfa;margin-bottom:.5rem}}
.hp-chip-list{{display:flex;flex-wrap:wrap;gap:.35rem}}
.pa-panel{{background:#0f1117;border:1px solid #252525;border-radius:6px;padding:.6rem .85rem .65rem;margin:0 0 1rem}}
.pa-title{{font-size:.68rem;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin:0 0 .45rem}}
.pa-list{{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:.28rem}}
.pa-item{{display:flex;align-items:baseline;gap:.4rem;font-size:.82rem;line-height:1.4}}
.pa-num{{flex-shrink:0;font-size:.63rem;font-weight:700;color:#444;width:1.1em;text-align:right}}
.pa-text{{flex:1;color:#c9d1d9}}
.pa-count{{flex-shrink:0;font-size:.61rem;font-weight:700;background:rgba(88,130,240,.1);color:#6ea8fe;border:1px solid rgba(88,130,240,.2);border-radius:3px;padding:1px 5px}}
.catchup-strip{{background:#0c1420;border:1px solid rgba(88,130,240,.25);border-radius:6px;margin:0 0 1rem;overflow:hidden}}
.catchup-summary{{display:flex;align-items:center;gap:.5rem;padding:.45rem .75rem;cursor:pointer;list-style:none;font-size:.81rem;color:#79b8ff;user-select:none}}
.catchup-summary::-webkit-details-marker{{display:none}}
.catchup-summary:hover{{background:rgba(88,130,240,.07)}}
.catchup-label{{flex:1;display:flex;flex-direction:column;gap:.2rem}}
.catchup-close{{flex-shrink:0;font-size:.85rem;opacity:.5}}
.catchup-body{{padding:.1rem .5rem .45rem}}
.cu-chips{{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.2rem}}
.cu-chip{{font-size:.65rem;padding:.1rem .4rem;border-radius:3px;background:#1e2a3a;color:#79b8ff;font-weight:600}}
.cu-chip--p1{{background:#3a1a1a;color:#f85149}}
.cu-chip--active{{background:#1a2a1a;color:#3fb950}}
.cu-chip--patch{{background:#2a2a1a;color:#e3b341}}
.cu-section-label{{font-size:.65rem;text-transform:uppercase;letter-spacing:.06em;color:#666;font-weight:700;padding:.3rem .25rem .1rem}}
.cu-row{{display:flex;align-items:center;gap:.32rem;padding:.22rem .25rem;border-radius:4px;cursor:pointer;font-size:.78rem}}
.cu-row:hover{{background:#1e2a3a}}
.cu-patch-row{{display:flex;align-items:center;gap:.4rem;padding:.22rem .25rem;border-radius:4px;cursor:pointer;font-size:.75rem}}
.cu-patch-row:hover{{background:#1e2a3a}}
.cu-patch-cve{{font-family:monospace;font-size:.72rem;color:#8b949e;min-width:120px}}
.cu-ps{{font-size:.68rem;padding:.1rem .3rem;border-radius:3px;font-weight:600}}
.cu-ps--good{{background:#1a3a1a;color:#3fb950}}.cu-ps--warn{{background:#2a2a1a;color:#e3b341}}.cu-ps--bad{{background:#3a1a1a;color:#f85149}}.cu-ps--neutral{{background:#252525;color:#8b949e}}
.cu-patch-arrow{{color:#555;font-size:.8rem}}
.cu-patch-title{{color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}}
.cu-score{{flex-shrink:0;font-size:.61rem;font-weight:700;background:#1a2535;color:#6ea8fe;border:1px solid rgba(88,130,240,.2);border-radius:3px;padding:1px 5px;min-width:2em;text-align:center}}
.cu-pri{{flex-shrink:0;font-size:.61rem;font-weight:700;border-radius:3px;padding:1px 5px}}
.cu-p1{{background:rgba(180,20,20,.12);color:#ff6b6b;border:1px solid rgba(180,20,20,.3)}}
.cu-p2{{background:rgba(180,100,20,.1);color:#f0a050;border:1px solid rgba(180,100,20,.25)}}
.cu-title{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#c9d1d9}}
.cu-more{{font-size:.72rem;color:#4a5568;padding:.1rem .25rem .25rem}}
.hp-chip{{display:inline-flex;align-items:center;gap:.3rem;background:rgba(139,92,246,.1);color:#c4b5fd;border:1px solid rgba(139,92,246,.25);border-radius:999px;font-size:.71rem;padding:2px 10px;font-weight:600}}
.hp-chip-count{{background:rgba(139,92,246,.3);color:#ede9fe;border-radius:999px;font-size:.65rem;font-weight:700;padding:0 5px;min-width:1.2em;text-align:center}}
.delta-strip{{display:flex;align-items:center;gap:.5rem;margin:.2rem 0 1rem;flex-wrap:wrap;min-height:1.6rem}}
.delta-chip{{display:inline-flex;align-items:center;border-radius:999px;padding:3px 11px;font-size:.71rem;font-weight:700;border:1px solid;letter-spacing:.03em}}
.delta-chip--new{{background:rgba(100,100,100,.12);color:#aaa;border-color:rgba(100,100,100,.3)}}
.delta-chip--elevated{{background:rgba(158,106,3,.12);color:#d29922;border-color:rgba(158,106,3,.3)}}
.delta-chip--resolved{{background:rgba(35,134,54,.12);color:#3fb950;border-color:rgba(35,134,54,.3)}}
.delta-chip--quiet{{color:#8b949e;border-color:#333;background:transparent}}
.resolved-drawer{{margin:.5rem 0 1rem;color:#8b949e}}
.resolved-drawer summary{{font-size:.8rem;cursor:pointer;padding:.3rem 0;list-style:none}}
.resolved-drawer summary::-webkit-details-marker{{display:none}}
.resolved-drawer table{{width:100%;border-collapse:collapse;font-size:.78rem;margin-top:.4rem}}
.resolved-drawer th{{font-size:.68rem;color:#777;font-weight:700;border-bottom:1px solid #252525;padding:.2rem .4rem}}
.resolved-drawer td{{padding:.25rem .4rem;border-bottom:1px solid #252525}}
.ha-section{{margin:0 0 1rem}}.ha-day{{border-bottom:1px solid #252525}}.ha-day:last-child{{border-bottom:none}}
.ha-summary{{display:flex;align-items:center;gap:.7rem;padding:.42rem .3rem;cursor:pointer;list-style:none;font-size:.82rem}}.ha-summary::-webkit-details-marker{{display:none}}
.ha-date{{font-weight:700;color:#e6edf3;flex:0 0 92px}}.ha-meta{{color:#c9d1d9;flex:1;font-size:.78rem}}.ha-ts{{color:#8b949e;font-size:.68rem;margin-left:auto;flex-shrink:0}}
.ha-lifecycle{{display:flex;gap:.35rem;flex-shrink:0}}.ha-lc{{font-size:.65rem;padding:.1rem .35rem;border-radius:3px;font-weight:600;letter-spacing:.02em}}.ha-lc--active{{background:#1a2a3a;color:#58a6ff}}.ha-lc--resolved{{background:#1a3a1a;color:#3fb950}}.ha-lc--escalated{{background:#3a1a1a;color:#f85149}}
.ha-body{{padding:.25rem .2rem .5rem .5rem}}.ha-table{{width:100%;border-collapse:collapse;font-size:.76rem}}.ha-table th{{font-size:.67rem;color:#777;font-weight:700;border-bottom:1px solid #252525;padding:.2rem .35rem}}
.ha-table td{{padding:.22rem .35rem;border-bottom:1px solid #1a1a1a;vertical-align:top}}.ha-title{{max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.ha-risk{{text-align:right;font-weight:700;color:#e6edf3;min-width:30px}}.ha-pri{{text-align:center;min-width:40px;white-space:nowrap}}
.weekly-scope{{margin:0 0 1rem}}.weekly-window-note{{font-size:.7rem;color:#8b949e;font-weight:400;margin-left:.4rem;vertical-align:middle}}.weekly-kpi-row{{display:flex;gap:10px;flex-wrap:wrap;margin:.4rem 0 .75rem}}
.wkpi{{background:#0f0f0f;border:1px solid #252525;border-radius:5px;padding:.4rem .65rem;display:flex;flex-direction:column;gap:.15rem;min-width:110px}}
.wk{{font-size:.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700}}.wv{{font-size:1.1rem;color:#e6edf3;font-weight:800}}.wv-sm{{font-size:.85rem}}.wv-cross{{font-size:1.1rem;color:#e6edf3;font-weight:800}}.wv-cross small{{font-size:.7rem;color:#8b949e;font-weight:400}}.wk-sub{{font-size:.62rem;color:#666}}.wv-good{{font-size:1.1rem;color:#3fb950;font-weight:800}}.wv-muted{{font-size:1.1rem;color:#444;font-weight:800}}.wkpi--good{{border-color:#1a3a1a}}.wkpi--spark{{min-width:80px}}.wv-spark{{display:flex;align-items:center;padding:.15rem 0}}.vel-spark{{display:block;color:#60a5fa}}
.weekly-review-label{{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;font-weight:700;color:#999;margin:.3rem 0 .2rem}}
.weekly-review-text{{margin:0 0 .7rem;line-height:1.75;font-size:.9rem;color:#c9d1d9}}
.wcve-details{{margin:.3rem 0 0}}.wcve-details summary{{font-size:.78rem;color:#8b949e;cursor:pointer;padding:.25rem 0;list-style:none}}.wcve-details summary::-webkit-details-marker{{display:none}}
.wcve-table{{width:100%;border-collapse:collapse;font-size:.76rem;margin-top:.35rem}}.wcve-table th{{font-size:.67rem;color:#777;font-weight:700;border-bottom:1px solid #252525;padding:.2rem .4rem}}.wcve-table td{{padding:.22rem .4rem;border-bottom:1px solid #1a1a1a}}
.wcve-id{{font-family:monospace;color:#999;font-size:.75rem}}.wcve-bar-cell{{min-width:80px}}.wcve-bar-inner{{height:5px;background:#666;border-radius:2px;min-width:2px}}.wcve-count{{text-align:right;font-weight:700;color:#e6edf3;min-width:22px}}
.threat-section{{display:block;margin:0 0 1rem}}
.threat-main{{padding:.3rem .4rem .5rem}}
.threat-toolbar{{display:flex;justify-content:space-between;align-items:center;padding:.3rem .3rem .45rem}}
.threat-title{{font-size:.9rem;font-weight:700;color:#e6edf3}}
.threat-sub{{font-size:.72rem;color:#8b949e}}
.right-rail{{position:fixed;right:0;top:0;bottom:0;width:var(--rail-width);padding:.8rem .7rem;display:flex;flex-direction:column;overflow:hidden;z-index:25;transition:width .2s ease,transform .22s ease;background:#1a1a1a;border:none;border-left:1px solid #2a2a2a;border-radius:0;box-shadow:-2px 0 8px rgba(0,0,0,.15)}}
body.rail-collapsed .right-rail{{width:var(--rail-width-collapsed);padding:.8rem .45rem}}
.rail-header{{display:flex;align-items:center;justify-content:space-between;gap:.4rem;padding:0 0 .45rem;border-bottom:1px solid #2a2a2a}}
.rail-actions{{display:flex;gap:.35rem;align-items:center}}
.rail-btn{{background:#151515;border:1px solid #3a3a3a;color:#aaa;border-radius:4px;font-size:.72rem;padding:.2rem .45rem;cursor:pointer}}
.rail-btn:hover{{background:#202020}}
.rail-content{{overflow:auto;padding:.5rem .05rem .2rem;display:flex;flex-direction:column;gap:.35rem}}
body.rail-collapsed .rail-content,body.rail-collapsed .rail-header h3{{display:none}}
.rail-collapsed-pill{{display:none;writing-mode:vertical-rl;transform:rotate(180deg);font-size:.72rem;letter-spacing:.04em;color:#8b949e;margin:.2rem auto 0}}
body.rail-collapsed .rail-collapsed-pill{{display:block}}
.rail-handle{{position:absolute;left:-4px;top:0;bottom:0;width:8px;cursor:ew-resize;background:linear-gradient(to right,rgba(160,160,160,.18),rgba(160,160,160,0));border-radius:3px;opacity:.4}}
.rail-handle:hover{{opacity:.85;background:linear-gradient(to right,rgba(180,180,180,.35),rgba(180,180,180,0))}}
.rail-tablist{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin:.1rem 0 .2rem}}
.rail-tab{{border:1px solid #333;background:#181818;color:#999;font-size:.68rem;padding:.24rem .2rem;border-radius:4px;text-align:center;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.rail-tab[aria-selected="true"]{{background:#2a2a2a;color:#c9d1d9;border-color:#555}}
.rail-panel{{display:none}}
.rail-panel.active{{display:block}}
.rail-placeholder{{font-size:.78rem;color:#8b949e;line-height:1.5;padding:.3rem 0}}
.alerts-subhdr{{font-size:.68rem;font-weight:700;color:#8b949e;letter-spacing:.04em;text-transform:uppercase;margin:.65rem 0 .2rem;padding-bottom:.15rem;border-bottom:1px solid #2a2a2a}}
.alerts-subhdr:first-child{{margin-top:.1rem}}
.alerts-cnt{{font-size:.62rem;font-weight:600;background:#252525;color:#6a7a8a;border-radius:999px;padding:1px 6px;margin-left:.3rem;text-transform:none;letter-spacing:0}}
.alert-row{{display:flex;align-items:center;gap:.3rem;padding:.26rem .2rem;border-radius:4px;cursor:pointer;font-size:.75rem;line-height:1.3}}
.alert-row:hover{{background:#1e2a3a}}
.alert-score{{flex-shrink:0;font-size:.61rem;font-weight:700;border-radius:3px;padding:1px 5px;min-width:2em;text-align:center}}
.alert-title{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#c9d1d9}}
.alert-annot{{flex-shrink:0;font-size:.61rem;font-weight:600;border-radius:3px;padding:1px 5px}}
.alert-annot--persist{{background:rgba(210,90,20,.1);color:#e8864a;border:1px solid rgba(210,90,20,.25)}}
.alert-annot--elevated{{background:rgba(40,160,80,.1);color:#56d364;border:1px solid rgba(40,160,80,.25)}}
.alert-annot--p1{{background:rgba(180,20,20,.12);color:#ff6b6b;border:1px solid rgba(180,20,20,.3)}}
.alert-annot--attr{{background:rgba(180,140,10,.1);color:#d4a017;border:1px solid rgba(180,140,10,.25)}}
.alert-empty{{font-size:.74rem;color:#4a5568;padding:.15rem 0 .35rem}}
.alert-highlight{{outline:2px solid rgba(88,130,240,.45);outline-offset:2px}}
.rail-mobile-toggle{{display:none;position:fixed;right:14px;bottom:14px;z-index:16;background:#252525;border:1px solid #444;color:#ccc;border-radius:999px;padding:.42rem .8rem;font-size:.74rem;cursor:pointer}}
.rail-backdrop{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.58);backdrop-filter:blur(1px);z-index:14}}
body.rail-open .rail-backdrop{{display:block}}
.tm-node .node-disc{{transition:stroke .12s,stroke-width .12s}}
.tm-node:hover .node-disc{{stroke:rgba(160,160,160,0.5)!important;stroke-width:1.4px!important}}
.tm-node .sel-indicator{{opacity:0;transition:opacity .18s}}
.tm-node.tm-selected .sel-indicator{{opacity:1}}
.rank-row{{display:flex;align-items:center;gap:6px;padding:.28rem 0;border-bottom:1px solid #222;cursor:pointer;border-radius:3px}}
.rank-row:hover{{background:rgba(255,255,255,.03)}}
.rank-label{{font-size:.77rem;flex:0 0 92px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.rank-bar-wrap{{flex:1;background:#181818;border-radius:2px;height:3px}}
.rank-bar{{height:3px;border-radius:2px;min-width:1px}}
.rank-val{{font-size:.7rem;font-weight:700;flex:0 0 22px;text-align:right}}
.chip{{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #333;background:#252525;color:#c9d1d9;font-size:.72rem}}
.next-run{{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;border:1px solid #3a3a3a;background:#1a1a1a;color:#999;font-size:.72rem;font-variant-numeric:tabular-nums;margin-left:.6rem}}
.next-run.soon{{border-color:#4a2a00;background:#1c1000;color:#e3a020}}
.next-run.now{{border-color:#2a3a2a;background:#151f15;color:#3fb950;animation:pulse-now 1s ease-in-out infinite}}
@keyframes pulse-now{{0%,100%{{opacity:1}}50%{{opacity:.55}}}}
footer{{color:#8b949e;font-size:.8rem;margin-top:2rem;padding-top:.8rem;border-top:1px solid #333}}
@media (max-width:900px){{
  :root{{--page-gutter:12px}}
  .header-bar{{padding:.45rem 12px}}
  .header-content{{padding-right:0!important}}
  body.rail-collapsed .header-content{{padding-right:0!important}}
  .header-bar h1{{font-size:1.02rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .header-bar p{{font-size:.72rem;display:flex;align-items:center;gap:.2rem;flex-wrap:nowrap;overflow:hidden}}
  .next-run{{font-size:.64rem;padding:2px 6px;margin-left:.3rem;flex-shrink:0}}
  .app-shell{{padding-top:68px}}
  .app-main{{padding:0 var(--page-gutter) 1rem;padding-right:var(--page-gutter)}}
  body.rail-collapsed .app-main{{padding-right:var(--page-gutter)}}
  .kpi-grid{{grid-template-columns:repeat(3,1fr);gap:6px;margin:.65rem 0 .85rem}}
  .kpi:last-child{{grid-column:1/-1;flex-direction:row;align-items:center;justify-content:space-between;padding:.38rem .75rem}}
  .kpi{{padding:.4rem .5rem}}
  .kpi .v{{font-size:1.05rem}}
  .kpi .v-sm{{font-size:.88rem}}
  .cluster summary{{flex-wrap:wrap;row-gap:.2rem;padding:.55rem .7rem}}
  .domain-tags{{margin:.15rem 0 0!important}}
  .matrix-panel{{display:none}}
  .executive{{padding:.6rem .85rem;margin:.5rem 0 1rem}}
  .hp-panel{{padding:.5rem .8rem .55rem}}
  .findings-filter{{gap:.4rem}}
  .findings-search{{width:100%}}
  .ha-title{{max-width:min(55vw,260px)}}
  h2{{font-size:1rem;margin:.75rem 0 .25rem}}
  .threat-toolbar{{flex-wrap:wrap;gap:.25rem}}
  .delta-strip{{margin:.1rem 0 .6rem}}
  .weekly-kpi-row{{gap:7px}}
  .right-rail{{right:0;top:0;bottom:0;width:min(92vw,420px);max-width:92vw;transform:translateX(100%);border-radius:0;box-shadow:-4px 0 12px rgba(0,0,0,.25)}}
  body.rail-open .right-rail{{transform:translateX(0)}}
  .rail-mobile-toggle{{display:inline-flex;align-items:center;gap:6px}}
}}
@media (max-width:480px){{
  .header-bar h1{{font-size:.92rem}}
  .next-run{{display:none}}
  .kpi-grid{{gap:5px;margin:.5rem 0 .7rem}}
  .kpi .k{{font-size:.6rem;letter-spacing:0}}
  .kpi .v{{font-size:.9rem}}
  .kpi:last-child .kpi .k{{font-size:.62rem}}
  .cluster summary{{font-size:.84rem;padding:.48rem .6rem;gap:.18rem}}
  .badge{{font-size:.67rem;padding:1px 6px}}
  .priority{{font-size:.62rem;padding:1px 5px}}
  .patch-badge,.cve-badge,.hp-badge{{font-size:.6rem;padding:1px 5px}}
  .ha-pri,.ha-ps{{display:none}}
  .wkpi{{min-width:76px;padding:.35rem .5rem}}
  .wv{{font-size:.95rem}}
  .cluster-body{{padding:.15rem .7rem .7rem}}
  footer{{font-size:.72rem}}
}}
.forensics-section-title{{font-size:.78rem;color:#e6edf3;text-transform:uppercase;letter-spacing:.05em;font-weight:700;margin:.9rem 0 .3rem;padding-top:.55rem;border-top:1px solid #2a2a2a}}
.forensics-section-title:first-child{{margin-top:.1rem;border-top:none}}
.forensics-hint{{font-size:.7rem;color:#6a7f98;margin:.1rem 0 .35rem;font-style:italic}}
.forensics-empty{{color:#8b949e;font-size:.77rem;font-style:italic;padding:.25rem 0}}
.forensics-table{{width:100%;border-collapse:collapse;font-size:.77rem}}
.forensics-table th,.forensics-table td{{border-bottom:1px solid #222;padding:.3rem .2rem;text-align:left}}
.forensics-table th{{color:#8b949e;font-size:.67rem;text-transform:uppercase;letter-spacing:.03em}}
.forensics-table tr:hover{{background:rgba(255,255,255,.03)}}
.forensics-acc{{border:1px solid #2a2a2a;border-radius:4px;margin:.2rem 0}}
.forensics-acc summary{{padding:.32rem .5rem;cursor:pointer;color:#c9d1d9;font-size:.82rem;list-style:none;display:flex;align-items:center;gap:.4rem}}
.forensics-acc summary::-webkit-details-marker{{display:none}}
.forensics-acc summary::before{{content:"›";font-size:.85rem;transition:transform .15s;flex-shrink:0;color:#8b949e;width:.7rem;text-align:center}}
.forensics-acc[open] summary::before{{transform:rotate(90deg)}}
.forensics-ioc-type{{color:#8b949e;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;margin:.55rem 0 .2rem;padding:0}}
.stale-banner{{background:#7d6608;color:#f0e68c;text-align:center;padding:.45rem 1rem;font-size:.82rem;position:sticky;top:0;z-index:200;letter-spacing:.02em}}
        </style>
        </head>
        <body>
        <div class="rail-backdrop" id="rail-backdrop"></div>
        <button id="rail-mobile-toggle" class="rail-mobile-toggle" type="button" aria-controls="domain-rail" aria-expanded="false">Domain Activity</button>
        <header class="header-bar">
          <div class="header-content">
            <h1>Watchtower — Infrastructure Security Briefing</h1>
            <p>Generated <strong>{ts.replace('_', ' ')}</strong> UTC | <a href="latest.md">latest.md</a><span class="next-run" id="next-run-cd" title="Scheduled: 2× daily">Next run —</span></p>
          </div>
        </header>
        <div class="page-wrap">
        <div class="app-shell">
        <main class="app-main">
        {f'<div class="executive"><h2>Analyst Summary</h2><p>{html.escape(executive)}</p></div>' if executive else ''}
{kpi_html}
{delta_strip_html}
{hp_panel_html}
{priority_actions_html}
<section class="threat-section">
  <div class="panel threat-main">
    <div class="threat-toolbar">
      <div>
        <div class="threat-title">Surface Threat Map</div>
        <div class="threat-sub">Domain constellation — node intensity shows activity heat, edges show blast-radius pathways. Click any node to filter findings.</div>
      </div>
      <span class="chip" title="Data polled from the last {since_hours} hours">{_window_chip}</span>
    </div>
    {threat_svg}
  </div>
</section>
{history_section}
{weekly_html}
{tactic_strip_html}
<h2>Top Findings</h2>
<div class="findings-filter">
  <input type="search" id="findings-search" class="findings-search" placeholder="Search findings\u2026" aria-label="Search findings" />
  <span id="findings-count" class="findings-count"></span>
</div>
{rows}
{resolved_drawer_html}
<footer>Watchtower · scheduled 2× daily · <span id="utc-clock"></span> · placeholder mode: {str(placeholder_mode()).lower()}</footer>
                </main>
                <aside id="domain-rail" class="panel right-rail" role="complementary" aria-label="Domain Activity">
                    <div class="rail-handle" id="rail-handle" role="separator" aria-orientation="vertical" aria-label="Resize Domain Activity panel"></div>
                    <div class="rail-header">
                        <h3 style="margin:.2rem 0 .2rem">Domain Activity</h3>
                        <div class="rail-actions">
                            <button id="rail-toggle" class="rail-btn" type="button" aria-expanded="true">Collapse</button>
                            <button id="rail-close" class="rail-btn" type="button" style="display:none">Close</button>
                        </div>
                    </div>
                    <div class="rail-collapsed-pill">DOMAIN ACTIVITY</div>
                    <div class="rail-content" id="rail-content">
                        <div class="rail-tablist" role="tablist" aria-label="Domain Activity modules">
                            <button class="rail-tab" type="button" id="tab-overview" role="tab" aria-controls="panel-overview" aria-selected="true" data-tab="overview">Overview</button>
                            <button class="rail-tab" type="button" id="tab-feeds" role="tab" aria-controls="panel-feeds" aria-selected="false" data-tab="feeds">Feeds</button>
                            <button class="rail-tab" type="button" id="tab-alerts" role="tab" aria-controls="panel-alerts" aria-selected="false" data-tab="alerts">Alerts</button>
                            <button class="rail-tab" type="button" id="tab-forensics" role="tab" aria-controls="panel-forensics" aria-selected="false" data-tab="forensics">Forensics</button>
                        </div>
                        <section class="rail-panel active" id="panel-overview" role="tabpanel" aria-labelledby="tab-overview">
                            {domain_rank_html}
                            <h3 style="margin:.7rem 0 .35rem">Selected Domain</h3>
                            <div id="tm-detail" class="muted" style="font-size:.8rem">Click a node to inspect findings.</div>
                        </section>
                        <section class="rail-panel" id="panel-feeds" role="tabpanel" aria-labelledby="tab-feeds">
                            <h3 style="margin:.2rem 0 .35rem">Run Metrics</h3>
                            {run_metrics_html}
                            <h3 style="margin:.6rem 0 .35rem">Feed Health</h3>
                            <table class="feed-table"><thead><tr><th>Feed</th><th>Items</th><th>Reliability</th><th>Time</th></tr></thead><tbody>{health_rows}</tbody></table>
                            <h3 style="margin:.6rem 0 .35rem">Source References</h3>
                            <table class="feed-table"><thead><tr><th>Domain</th><th>Refs</th><th>Max risk</th></tr></thead><tbody>{feed_rows}</tbody></table>
                        </section>
                        <section class="rail-panel" id="panel-alerts" role="tabpanel" aria-labelledby="tab-alerts">
                            <h3 style="margin:.2rem 0 .35rem">Alerts</h3>
                            {alerts_html}
                        </section>
                        <section class="rail-panel" id="panel-forensics" role="tabpanel" aria-labelledby="tab-forensics">
                            <h3 style="margin:.2rem 0 .35rem">Forensics</h3>
                            {forensics_html}
                        </section>
                    </div>
                </aside>
                </div>
                </div>
<script>
var CARDS={json.dumps(card_data)};
var CURRENT_DOMAIN='all';
var DOMAIN_LABELS={json.dumps({k: v.get('label', k) for k, v in heatmap.items()})};
var WT_TELEMETRY=[];

function trackUi(evt,payload){{
        var e={{event:evt,ts:new Date().toISOString(),payload:payload||{{}}}};
        WT_TELEMETRY.push(e);
}}

function isNarrow(){{return window.matchMedia('(max-width: 900px)').matches;}}

function applyRailWidth(w){{
        var min=320,max=480;
        var n=Math.max(min,Math.min(max,Math.round(w||360)));
        document.documentElement.style.setProperty('--rail-width',n+'px');
        try{{localStorage.setItem('wt.rail.width',String(n));}}catch(e){{}}
        window.dispatchEvent(new Event('resize'));
}}

function setRailCollapsed(collapsed,persist){{
        document.body.classList.toggle('rail-collapsed',!!collapsed);
        var t=document.getElementById('rail-toggle');
        if(t){{
                t.textContent=collapsed?'Expand':'Collapse';
                t.setAttribute('aria-expanded',(!collapsed).toString());
        }}
        if(persist!==false){{
                try{{localStorage.setItem('wt.rail.collapsed',collapsed?'1':'0');}}catch(e){{}}
        }}
        trackUi(collapsed?'rail_collapsed':'rail_expanded');
        window.dispatchEvent(new Event('resize'));
}}

function setRailOpen(open,persist){{
        document.body.classList.toggle('rail-open',!!open);
        var mt=document.getElementById('rail-mobile-toggle');
        if(mt) mt.setAttribute('aria-expanded',open?'true':'false');
        if(persist!==false){{
                try{{localStorage.setItem('wt.rail.mobileOpen',open?'1':'0');}}catch(e){{}}
        }}
        trackUi(open?'rail_opened':'rail_closed',{{mobile:isNarrow()}});
}}

function setRailTab(tab){{
        document.querySelectorAll('.rail-tab').forEach(function(btn){{
                var active=btn.getAttribute('data-tab')===tab;
                btn.setAttribute('aria-selected',active?'true':'false');
                btn.tabIndex=active?0:-1;
        }});
        document.querySelectorAll('.rail-panel').forEach(function(p){{
                p.classList.toggle('active',p.id==='panel-'+tab);
        }});
        try{{localStorage.setItem('wt.rail.tab',tab);}}catch(e){{}}
        trackUi('rail_tab',{{tab:tab}});
}}

function initRightRail(){{
        var toggle=document.getElementById('rail-toggle');
        var close=document.getElementById('rail-close');
        var mobileToggle=document.getElementById('rail-mobile-toggle');
        var backdrop=document.getElementById('rail-backdrop');
        var handle=document.getElementById('rail-handle');

        var initialTab='overview';
        try{{initialTab=localStorage.getItem('wt.rail.tab')||'overview';}}catch(e){{}}
        setRailTab(initialTab);

        var savedW=360;
        try{{savedW=parseInt(localStorage.getItem('wt.rail.width')||'360',10)||360;}}catch(e){{}}
        applyRailWidth(savedW);

        var collapsed=false;
        try{{collapsed=localStorage.getItem('wt.rail.collapsed')==='1';}}catch(e){{}}
        if(!isNarrow()) setRailCollapsed(collapsed,false);

        document.querySelectorAll('.rail-tab').forEach(function(btn){{
                btn.addEventListener('click',function(){{ setRailTab(btn.getAttribute('data-tab')); }});
        }});

        if(toggle) toggle.addEventListener('click',function(){{ setRailCollapsed(!document.body.classList.contains('rail-collapsed')); }});
        if(mobileToggle) mobileToggle.addEventListener('click',function(){{ setRailOpen(true); }});
        if(close) close.addEventListener('click',function(){{ setRailOpen(false); }});
        if(backdrop) backdrop.addEventListener('click',function(){{ setRailOpen(false); }});
        document.addEventListener('keydown',function(e){{ if(e.key==='Escape') setRailOpen(false); }});

        if(handle){{
                var dragging=false;
                handle.addEventListener('pointerdown',function(e){{
                        if(isNarrow()) return;
                        dragging=true;
                        handle.setPointerCapture(e.pointerId);
                        document.body.style.userSelect='none';
                        trackUi('rail_resize_start');
                }});
                handle.addEventListener('pointermove',function(e){{
                        if(!dragging||isNarrow()) return;
                        var w=(window.innerWidth-e.clientX)-parseInt(getComputedStyle(document.documentElement).getPropertyValue('--page-gutter')||16,10);
                        applyRailWidth(w);
                }});
                handle.addEventListener('pointerup',function(){{
                        if(!dragging) return;
                        dragging=false;
                        document.body.style.userSelect='';
                        var cur=parseInt(getComputedStyle(document.documentElement).getPropertyValue('--rail-width')||'360',10);
                        trackUi('rail_resized',{{width:cur}});
                }});
        }}

        var mq=window.matchMedia('(max-width: 900px)');
        function onViewport(){{
                if(close) close.style.display=isNarrow()?'inline-block':'none';
                if(!isNarrow()){{ setRailOpen(false,false); }}
                window.dispatchEvent(new Event('resize'));
        }}
        if(mq.addEventListener) mq.addEventListener('change',onViewport); else mq.addListener(onViewport);
        onViewport();
}}

function selectDomain(domain){{
    CURRENT_DOMAIN = domain||'all';
    document.querySelectorAll('.tm-node').forEach(function(g){{ g.classList.remove('tm-selected'); }});
    if(domain&&domain!=='all'){{
        var n=document.querySelector('.tm-node[data-domain="'+domain+'"]');
        if(n) n.classList.add('tm-selected');
    }}
    document.querySelectorAll('.cluster').forEach(function(el){{
        if(CURRENT_DOMAIN==='all'){{el.style.display='block';return;}}
        var ds=(el.getAttribute('data-domains')||'').split(/\\s+/);
        el.style.display=ds.indexOf(CURRENT_DOMAIN)>=0?'block':'none';
    }});
    var subset=CURRENT_DOMAIN==='all'?CARDS:CARDS.filter(function(c){{return(c.domains||[]).indexOf(CURRENT_DOMAIN)>=0;}});
    var p1=subset.filter(function(c){{return c.priority==='P1';}}).length;
    var maxRisk=subset.reduce(function(m,c){{return Math.max(m,c.risk_score||0);}},0);
    var lbl=DOMAIN_LABELS[domain]||domain||'All domains';
    var lines=subset.slice().sort(function(a,b){{return(b.risk_score||0)-(a.risk_score||0);}}).slice(0,8)
        .map(function(c){{
            var scoreChip='<span style="display:inline-block;min-width:1.8rem;text-align:center;'
                +'background:#1c2a1c;color:#4caf50;font-size:.65rem;font-weight:700;'
                +'border-radius:3px;padding:1px 4px;margin-right:.35rem">'+c.risk_score+'</span>';
            var priChip=c.priority==='P1'
                ?'<span style="color:#ff6b6b;font-size:.63rem;font-weight:700;margin-right:.25rem">P1</span>'
                :'';
            var snip=c.summary?'<div style="color:#6a7f98;font-size:.71rem;margin:.15rem 0 .3rem;'
                +'line-height:1.35;max-height:2.7em;overflow:hidden">'+c.summary.slice(0,110)+(c.summary.length>110?'\u2026':'')+'</div>':'';
            var srcLinks=(c.sources||[]).map(function(s){{
                return '<a href="'+s.url+'" target="_blank" rel="noopener noreferrer" '
                    +'style="display:block;color:#58a6ff;font-size:.68rem;white-space:nowrap;'
                    +'overflow:hidden;text-overflow:ellipsis;max-width:100%;margin:.08rem 0" '
                    +'title="'+s.title+'">\u2197\u00a0'+s.title+'</a>';
            }}).join('');
            return '<li style="margin:.45rem 0 .6rem;list-style:none;border-left:2px solid #2a2a2a;padding-left:.5rem">'
                +priChip+scoreChip
                +'<span style="color:#c9d1d9;font-size:.78rem;font-weight:500">'+c.title+'</span>'
                +snip
                +(srcLinks?'<div style="margin-top:.15rem">'+srcLinks+'</div>':'')
                +'</li>';
        }}).join('');
    var t=document.getElementById('tm-detail');
    if(t){{
        t.innerHTML='<strong style="color:#c9d1d9">'+lbl+'</strong>'
            +'<div style="color:#6a7f98;font-size:.75rem;margin:.2rem 0 .35rem">Findings: '+subset.length+' &middot; P1: '+p1+' &middot; Max risk: '+maxRisk+'</div>'
            +(lines?'<ul style="margin:.3rem 0 0 0;padding:0">'+lines+'</ul>':'<div style="color:#5a7090;font-size:.78rem">No findings in this window.</div>');
    }}
    trackUi('domain_selected',{{domain:CURRENT_DOMAIN,count:subset.length,maxRisk:maxRisk}});
}}
(function(){{
  var SLOTS=[6,18],MIN=5;
  var el=document.getElementById('next-run-cd');
  if(!el)return;
  var fmt=new Intl.DateTimeFormat('en-US',{{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}});
  function etP(d){{return fmt.formatToParts(d).reduce(function(a,p){{if(p.type!='literal')a[p.type]=+p.value;return a;}},{{}});}}
  function nextRun(now){{
    var et=etP(now);
    for(var d=0;d<2;d++){{
      for(var i=0;i<SLOTS.length;i++){{
        if(d===0&&(SLOTS[i]<et.hour||(SLOTS[i]===et.hour&&MIN<=et.minute)))continue;
        var noon=new Date(Date.UTC(et.year,et.month-1,et.day+d,12,0,0));
        var off=12-etP(noon).hour;
        var cand=new Date(Date.UTC(et.year,et.month-1,et.day+d,SLOTS[i]+off,MIN,0));
        if(cand>now)return cand;
      }}
    }}
    return new Date(now.getTime()+7*3600*1000);
  }}
  function pad(n){{return String(n).padStart(2,'0');}}
  function tick(){{
    var now=new Date(),next=nextRun(now);
    var diff=Math.max(0,Math.floor((next-now)/1000));
    var h=Math.floor(diff/3600),m=Math.floor((diff%3600)/60),s=diff%60;
    el.textContent='Next run '+pad(h)+':'+pad(m)+':'+pad(s);
    el.title='Next run: '+pad(next.getUTCHours())+':'+pad(next.getUTCMinutes())+' UTC';
    el.className='next-run'+(diff<600?' soon':'')+(diff<60?' now':'');
  }}
  tick();setInterval(tick,1000);
}})();
(function(){{
  var el=document.getElementById('utc-clock');
  function p(n){{return String(n).padStart(2,'0');}}
  function u(){{if(el){{var n=new Date();el.textContent=p(n.getUTCHours())+':'+p(n.getUTCMinutes())+':'+p(n.getUTCSeconds())+' UTC';}}}}
  u();setInterval(u,1000);
}})();
(function(){{
  var p1=Object.values(CARDS).filter(function(c){{return c.priority==='P1';}}).length;
  document.title=(p1?'['+p1+' P1] ':'')+'Watchtower \u2014 InfraSec Briefing';
}})();
(function(){{
  var el=document.querySelector('.header-content p strong');
  if(!el)return;
  var ts=el.textContent.trim().replace(' ','T')+'Z';
  var gen=new Date(ts);
  if(isNaN(gen))return;
  var ageH=(Date.now()-gen)/3600000;
  if(ageH>28){{
    var b=document.createElement('div');
    b.className='stale-banner';
    b.textContent='\u26a0 Briefing may be stale \u2014 generated '+Math.floor(ageH)+' hours ago';
    document.body.insertBefore(b,document.body.firstChild);
  }}
}})();
function initFindingsFilter(){{
  var inp=document.getElementById('findings-search');
  var allClusters=Array.from(document.querySelectorAll('.cluster'));
  var currentTactic='all';
  function applyFilters(){{
    var q=inp?inp.value.trim().toLowerCase():'';
    var visible=0;
    allClusters.forEach(function(el){{
      var inDomain=CURRENT_DOMAIN==='all'||(el.getAttribute('data-domains')||'').split(/\\s+/).indexOf(CURRENT_DOMAIN)>=0;
      var inTactic=currentTactic==='all'||(el.getAttribute('data-tactic')||'')=== currentTactic;
      var inSearch=!q||el.textContent.toLowerCase().includes(q);
      el.style.display=(inDomain&&inTactic&&inSearch)?'':'none';
      if(inDomain&&inTactic&&inSearch)visible++;
    }});
    var cnt=document.getElementById('findings-count');
    if(cnt)cnt.textContent=(q||currentTactic!=='all')?visible+' of '+allClusters.length+' shown':'';
  }}
  if(inp)inp.addEventListener('input',applyFilters);
  document.querySelectorAll('.tactic-btn').forEach(function(btn){{
    btn.addEventListener('click',function(){{
      currentTactic=btn.getAttribute('data-tactic');
      document.querySelectorAll('.tactic-btn').forEach(function(b){{b.classList.toggle('tactic-btn--active',b===btn);}});
      applyFilters();
    }});
  }});
}}
function forensicsCveClick(cve){{
    var inp=document.getElementById('findings-search');
    if(inp){{inp.value=cve;inp.dispatchEvent(new Event('input'));}}
    var overBtn=document.querySelector('[data-tab="overview"]');
    if(overBtn)overBtn.click();
}}
document.querySelectorAll('.alert-row[data-card-id]').forEach(function(row){{
  row.addEventListener('click',function(){{
    var id=row.getAttribute('data-card-id');
    var card=document.getElementById('card-'+id);
    if(card){{
      card.open=true;
      card.scrollIntoView({{behavior:'smooth',block:'center'}});
      card.classList.add('alert-highlight');
      setTimeout(function(){{card.classList.remove('alert-highlight');}},1800);
    }}
  }});
}});
(function(){{
  var lastVisit=0;
  try{{lastVisit=parseInt(localStorage.getItem('wt.last_visit')||'0',10)||0;}}catch(e){{}}
  var now=Date.now();
  /* Save CVE\u2192patch_status snapshot for next visit\u2019s change detection */
  var cveSnap={{}};
  (CARDS||[]).forEach(function(c){{
    (c.cves||[]).forEach(function(cve){{cveSnap[cve]=c.patch_status||'unknown';}});
  }});
  try{{localStorage.setItem('wt.last_visit',String(now));}}catch(e){{}}
  try{{localStorage.setItem('wt.cve_status',JSON.stringify(cveSnap));}}catch(e){{}}
  if(!lastVisit)return;
  var gapH=(now-lastVisit)/3600000;
  if(gapH<4)return;
  var gapDays=Math.floor(gapH/24);
  var awayLabel=gapDays>=1?(gapDays===1?'1 day':gapDays+' days'):Math.round(gapH)+'h';
  var lvDate=new Date(lastVisit).toISOString().slice(0,10);
  /* 1. New findings since last visit */
  var fresh=(CARDS||[]).filter(function(c){{return c.first_seen_ts&&c.first_seen_ts>=lvDate;}});
  /* 2. New P1s among those new findings */
  var newP1=fresh.filter(function(c){{return c.priority==='P1';}}).length;
  /* 3. Still-active persistent findings (existed before visit, still unresolved) */
  var stillActive=(CARDS||[]).filter(function(c){{return(c.run_count||1)>1&&!c.shelf_resolved;}}).length;
  /* 4. CVEs whose patch_status changed vs. last visit\u2019s snapshot */
  var prevSnap={{}};
  try{{prevSnap=JSON.parse(localStorage.getItem('wt.cve_status')||'{{}}');}}catch(e){{}}
  var patchChanged=[];
  (CARDS||[]).forEach(function(c){{
    (c.cves||[]).forEach(function(cve){{
      var prev=prevSnap[cve];
      var cur=c.patch_status||'unknown';
      if(prev&&prev!==cur)patchChanged.push({{cve:cve,from:prev,to:cur,title:c.title||'',id:c.id||''}});
    }});
  }});
  if(!fresh.length&&!patchChanged.length)return;
  /* Build headline chips */
  var chips='';
  if(fresh.length)chips+='<span class="cu-chip">'+fresh.length+' new</span>';
  if(newP1>0)chips+='<span class="cu-chip cu-chip--p1">P1: '+newP1+'</span>';
  if(stillActive>0)chips+='<span class="cu-chip cu-chip--active">'+stillActive+' still active</span>';
  if(patchChanged.length>0)chips+='<span class="cu-chip cu-chip--patch">'+patchChanged.length+' status changed</span>';
  /* Build new-findings rows */
  var findingRows=fresh.slice(0,10).map(function(c){{
    var pri=c.priority||'';
    var priHtml=pri&&(pri==='P1'||pri==='P2')?'<span class="cu-pri cu-'+(pri==='P1'?'p1':'p2')+'">'+pri+'</span>':'';
    var t=(c.title||'').slice(0,80).replace(/&/g,'&amp;').replace(/</g,'&lt;');
    return '<div class="cu-row" data-card-id="'+(c.id||'')+'" role="button" tabindex="0">'
      +'<span class="cu-score">'+(c.risk_score||0)+'</span>'
      +priHtml
      +'<span class="cu-title">'+t+'</span>'
      +'</div>';
  }}).join('');
  var more=fresh.length>10?'<div class="cu-more">+'+(fresh.length-10)+' more below</div>':'';
  /* Build patch-change rows */
  var patchRows='';
  if(patchChanged.length){{
    patchRows='<div class="cu-section-label">Patch status changes</div>'
      +patchChanged.slice(0,5).map(function(p){{
        var fCls=p.from==='no_fix'?'cu-ps--bad':'cu-ps--neutral';
        var tCls=p.to==='patched'?'cu-ps--good':p.to==='workaround'?'cu-ps--warn':'cu-ps--bad';
        var cve=(p.cve||'').replace(/&/g,'&amp;');
        var ttl=(p.title||'').slice(0,55).replace(/&/g,'&amp;').replace(/</g,'&lt;');
        return '<div class="cu-patch-row" data-card-id="'+p.id+'" role="button" tabindex="0">'
          +'<span class="cu-patch-cve">'+cve+'</span>'
          +'<span class="cu-ps '+fCls+'">'+p.from+'</span>'
          +'<span class="cu-patch-arrow">\u2192</span>'
          +'<span class="cu-ps '+tCls+'">'+p.to+'</span>'
          +'<span class="cu-patch-title">'+ttl+'</span>'
          +'</div>';
      }}).join('');
  }}
  var bodyHtml=(findingRows?'<div class="cu-section-label">New findings</div>'+findingRows+more:'')+patchRows;
  var strip=document.createElement('details');
  strip.className='catchup-strip';
  strip.open=true;
  strip.innerHTML='<summary class="catchup-summary">'
    +'<span>\u23f1</span>'
    +'<span class="catchup-label"><strong>You were away '+awayLabel+' \u2014 here\u2019s what changed</strong>'
    +'<span class="cu-chips">'+chips+'</span></span>'
    +'<span class="catchup-close">\u00d7</span>'
    +'</summary>'
    +'<div class="catchup-body">'+bodyHtml+'</div>';
  strip.querySelectorAll('[data-card-id]').forEach(function(row){{
    row.addEventListener('click',function(){{
      var card=document.getElementById('card-'+row.getAttribute('data-card-id'));
      if(card){{card.open=true;card.scrollIntoView({{behavior:'smooth',block:'center'}});card.classList.add('alert-highlight');setTimeout(function(){{card.classList.remove('alert-highlight');}},1800);}}
    }});
  }});
  var main=document.querySelector('.app-main');
  if(main)main.insertBefore(strip,main.firstChild);
}})();
initRightRail();
selectDomain('all');
initFindingsFilter();
</script>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(page_html)
