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
from agent.matrix import (
    AFFECTS_COLORS,
    AFFECTS_LABELS,
    AFFECTS_ORDER,
    PROBLEM_TYPE_LABELS,
    PROBLEM_TYPE_ORDER,
    bubble_radius,
    build_matrix_data,
    cell_geometry,
    cell_origin,
)
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


# ──────────────────────────────────────────────
# Threat matrix — problem_type × affects grid
# ──────────────────────────────────────────────


def _matrix_cell_fill(cell: dict | None) -> tuple:
    """Return (fill_alpha, glow_alpha, ring_alpha) for a cell heat treatment.

    Empty cells render almost invisibly so the populated cells dominate the
    eye.  Loud cells glow, but the gradient is restrained — saturation in the
    matrix should signal heat, not shout.
    """
    if not cell or cell.get("active_count", 0) == 0:
        return 0.03, 0.0, 0.06
    risk = cell.get("max_risk", 0) / 100.0
    density = min(1.0, cell.get("active_count", 0) / 5.0)
    # Cap fill alpha well below 0.5 so even hot cells stay visually quiet.
    fill = 0.07 + 0.30 * (0.6 * risk + 0.4 * density)
    glow = 0.15 + 0.40 * risk if cell.get("any_kev") else 0.08 + 0.22 * risk
    ring = 0.18 + 0.32 * risk
    return round(fill, 3), round(glow, 3), round(ring, 3)


def _build_threat_matrix_svg(matrix_data: dict) -> str:
    """Render the matrix grid (cells, axis labels, counts) as inline SVG.

    Bubbles are not rendered server-side — petite-vue (added in Phase 3) draws
    them client-side from ``WT_DATA.bubbles`` so the same SVG can react to the
    time-window slider without a Python rebuild.  Phase 2 ships only the cell
    skeleton with count chips so the grid is usable as-is.
    """
    g = cell_geometry()
    pts = matrix_data.get("problem_types", PROBLEM_TYPE_ORDER)
    afs = matrix_data.get("affects", AFFECTS_ORDER)
    pt_labels = matrix_data.get("problem_type_labels", PROBLEM_TYPE_LABELS)
    af_labels = matrix_data.get("affects_labels", AFFECTS_LABELS)
    af_colors = matrix_data.get("affects_colors", AFFECTS_COLORS)
    cells = matrix_data.get("cells", {})

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" id="wt-matrix-svg"'
        f' viewBox="0 0 {g["view_w"]} {g["view_h"]}"'
        f' preserveAspectRatio="xMidYMid meet"'
        f' style="width:100%;height:auto;display:block;'
        f'background:radial-gradient(ellipse at 50% 0%, #14181f 0%, #0a0c10 70%);'
        f'border-radius:10px;border:1px solid #1f242c">',
        "<defs>",
        # Cell gradient: top-bright fading to baseline — gives subtle depth
        '<linearGradient id="wt-cell-grad" x1="0%" y1="0%" x2="0%" y2="100%">'
        '<stop offset="0%" stop-color="white" stop-opacity="0.10"/>'
        '<stop offset="55%" stop-color="white" stop-opacity="0.02"/>'
        '<stop offset="100%" stop-color="black" stop-opacity="0.18"/>'
        "</linearGradient>",
        # Bubble inner gradient: lighter center, slightly darker edge
        '<radialGradient id="wt-bubble-grad" cx="35%" cy="30%" r="80%">'
        '<stop offset="0%" stop-color="white" stop-opacity="0.55"/>'
        '<stop offset="100%" stop-color="white" stop-opacity="0"/>'
        "</radialGradient>",
        # Soft outer glow — used on hovered/locked cells & urgent halos
        '<filter id="wt-soft-glow" x="-50%" y="-50%" width="200%" height="200%">'
        '<feGaussianBlur in="SourceGraphic" stdDeviation="3"/></filter>',
        '<filter id="wt-bubble-shadow" x="-80%" y="-80%" width="260%" height="260%">'
        '<feGaussianBlur in="SourceAlpha" stdDeviation="1.4"/>'
        '<feOffset dx="0" dy="0.6" result="off"/>'
        '<feFlood flood-color="black" flood-opacity="0.45"/>'
        '<feComposite in2="off" operator="in"/>'
        '<feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>'
        "</filter>",
        '<filter id="wt-bubble-halo" x="-100%" y="-100%" width="300%" height="300%">'
        '<feGaussianBlur stdDeviation="1.8"/></filter>',
        # Trajectory band fade — top edge softens out so the watermark feels
        # like a horizon rather than a jagged silhouette.
        '<linearGradient id="wt-traj-fade" x1="0%" y1="0%" x2="0%" y2="100%">'
        '<stop offset="0%" stop-color="white" stop-opacity="0"/>'
        '<stop offset="35%" stop-color="white" stop-opacity="0.55"/>'
        '<stop offset="100%" stop-color="white" stop-opacity="1"/>'
        "</linearGradient>",
        '<mask id="wt-traj-mask">'
        f'<rect x="0" y="0" width="{g["view_w"]}" height="{g["view_h"]}" fill="url(#wt-traj-fade)"/>'
        "</mask>",
        # Background dot grid — ambient texture so empty cells don't read as voids.
        '<pattern id="wt-dot-grid" x="0" y="0" width="14" height="14" patternUnits="userSpaceOnUse">'
        '<circle cx="0.6" cy="0.6" r="0.6" fill="#2a3140" fill-opacity="0.30"/>'
        "</pattern>",
        "</defs>",
        # Background dot texture (sits behind everything else)
        f'<rect x="{g["label_left"]}" y="{g["label_top"]}"'
        f' width="{g["grid_w"]}" height="{g["grid_h"]}"'
        f' fill="url(#wt-dot-grid)" pointer-events="none"/>',
        # Trajectory watermark anchor — populated by Phase 6 (uses traj-mask)
        '<g id="wt-trajectory" opacity="0"></g>',
    ]

    # Column labels (problem types) — refined: lower-weight, higher tracking,
    # mixed case with a dimmer fill so they recede behind the cell content.
    for ci, pt in enumerate(pts):
        x = g["label_left"] + ci * (g["cell_w"] + g["gutter_x"]) + g["cell_w"] / 2
        y = g["label_top"] - 9
        label = pt_labels.get(pt, pt)
        parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="middle"'
            f' font-family="system-ui,-apple-system,sans-serif" font-size="9.5"'
            f' font-weight="600" fill="#7a8493" letter-spacing="0.08em"'
            f' style="text-transform:uppercase">{html.escape(label)}</text>'
        )

    # Row labels + cells
    for ri, af in enumerate(afs):
        row_y = g["label_top"] + ri * (g["cell_h"] + g["gutter_y"]) + g["cell_h"] / 2
        af_label = af_labels.get(af, af)
        af_color = af_colors.get(af, "#94a3b8")
        # Row label with color swatch — taller, narrower swatch for elegance
        parts.append(
            f'<g class="wt-row-label" data-affects="{af}" style="cursor:pointer">'
            f'<rect x="{g["margin"]:.1f}" y="{row_y - 9:.1f}" width="2.5" height="18"'
            f' fill="{af_color}" opacity="0.78" rx="1.25"/>'
            f'<text x="{g["margin"] + 9:.1f}" y="{row_y + 4:.1f}"'
            f' font-family="system-ui,-apple-system,sans-serif" font-size="10.5"'
            f' font-weight="500" fill="#a5afbe">{html.escape(af_label)}</text>'
            f'</g>'
        )

        for ci, pt in enumerate(pts):
            cx, cy = cell_origin(ci, ri, g)
            cell_key = f"{pt}|{af}"
            cell = cells.get(cell_key)
            fill_a, glow_a, ring_a = _matrix_cell_fill(cell)
            row_rgb = af_color  # use row hue as cell tint
            active = cell.get("active_count", 0) if cell else 0
            p1 = cell.get("p1_count", 0) if cell else 0
            max_risk = cell.get("max_risk", 0) if cell else 0
            long_runner = cell.get("long_runner_count", 0) if cell else 0
            any_kev = bool(cell.get("any_kev")) if cell else False
            empty = active == 0 and (cell is None or cell.get("long_runner_count", 0) == 0)

            cls = "wt-cell" + (" wt-cell--empty" if empty else "")
            cls += " wt-cell--kev" if any_kev else ""
            af_label_disp = af_labels.get(af, af)
            pt_label_disp = pt_labels.get(pt, pt)
            aria_label = (
                f"{pt_label_disp} affecting {af_label_disp}, "
                f"{active} active findings"
                + (f", {p1} P1" if p1 else "")
                + (", contains KEV-listed CVE" if any_kev else "")
            )
            parts.append(
                f'<g class="{cls}" data-cell="{cell_key}" data-pt="{pt}" data-af="{af}"'
                f' role="button" tabindex="0" aria-label="{html.escape(aria_label)}"'
                f' style="cursor:pointer">'
            )
            # Layer 1 — base fill tinted by the row hue (low opacity).
            parts.append(
                f'<rect class="wt-cell-bg" x="{cx:.1f}" y="{cy:.1f}"'
                f' width="{g["cell_w"]}" height="{g["cell_h"]}"'
                f' rx="7" ry="7" fill="{row_rgb}" fill-opacity="{fill_a:.3f}"/>'
            )
            # Layer 2 — top-down sheen for depth (single shared gradient).
            if not empty:
                parts.append(
                    f'<rect class="wt-cell-sheen" x="{cx:.1f}" y="{cy:.1f}"'
                    f' width="{g["cell_w"]}" height="{g["cell_h"]}"'
                    f' rx="7" ry="7" fill="url(#wt-cell-grad)" pointer-events="none"/>'
                )
            # Layer 3 — outline.  Empty cells get a barely-there dotted hint;
            # populated cells get a soft solid stroke matching their row hue.
            if empty:
                parts.append(
                    f'<rect class="wt-cell-outline" x="{cx:.1f}" y="{cy:.1f}"'
                    f' width="{g["cell_w"]}" height="{g["cell_h"]}"'
                    f' rx="7" ry="7" fill="none" stroke="#1d2330"'
                    f' stroke-opacity="0.55" stroke-width="0.7"'
                    f' stroke-dasharray="1.5 3"/>'
                )
            else:
                parts.append(
                    f'<rect class="wt-cell-outline" x="{cx:.1f}" y="{cy:.1f}"'
                    f' width="{g["cell_w"]}" height="{g["cell_h"]}"'
                    f' rx="7" ry="7" fill="none" stroke="{row_rgb}"'
                    f' stroke-opacity="{ring_a:.3f}" stroke-width="0.8"/>'
                )
            # KEV indicator — small upper-left pulsing red dot.  This is one
            # of only two places red appears on the matrix (the other is P1
            # text).  Both flag genuine criticality.
            if any_kev:
                parts.append(
                    f'<circle class="wt-cell-kev-dot" cx="{cx + 7:.1f}"'
                    f' cy="{cy + 7:.1f}" r="2.2" fill="#ef4444"'
                    f' opacity="0.95"/>'
                )
            # Count + P1 + long-runner badges as a single compact metadata block,
            # right-aligned in the upper corner.
            if active > 0 or (cell and cell.get("long_runner_count", 0) > 0):
                chip_x = cx + g["cell_w"] - 7
                count_label = str(active) if active < 100 else "99+"
                parts.append(
                    f'<text class="wt-cell-count" x="{chip_x:.1f}" y="{cy + 14:.1f}"'
                    f' text-anchor="end" font-family="system-ui,-apple-system,sans-serif"'
                    f' font-size="10.5" font-weight="700" fill="#d4dce6"'
                    f' letter-spacing="0.01em">{count_label}</text>'
                )
                if p1 > 0:
                    parts.append(
                        f'<text class="wt-cell-p1" x="{chip_x:.1f}" y="{cy + 26:.1f}"'
                        f' text-anchor="end" font-family="system-ui,-apple-system,sans-serif"'
                        f' font-size="7.5" font-weight="700" fill="#ef4444"'
                        f' letter-spacing="0.05em">P1·{p1}</text>'
                    )
                if long_runner > 0:
                    parts.append(
                        f'<text class="wt-cell-runner" x="{cx + 7:.1f}"'
                        f' y="{cy + g["cell_h"] - 6:.1f}"'
                        f' font-family="system-ui,-apple-system,sans-serif"'
                        f' font-size="7.5" font-weight="600" fill="#7a8b9a"'
                        f' letter-spacing="0.04em" opacity="0.8">{long_runner} ongoing</text>'
                    )
            # Bubble layer (hydrated client-side).
            parts.append(
                f'<g class="wt-bubble-layer" data-cell="{cell_key}"'
                f' transform="translate({cx:.1f},{cy:.1f})"></g>'
            )
            # Selection treatment — twin rings: a soft inner glow ring (row hue)
            # and a thin neutral outer ring.  The stark white stroke is gone.
            parts.append(
                f'<rect class="wt-cell-sel-glow" x="{cx:.1f}" y="{cy:.1f}"'
                f' width="{g["cell_w"]}" height="{g["cell_h"]}"'
                f' rx="7" ry="7" fill="none" stroke="{row_rgb}"'
                f' stroke-opacity="0.85" stroke-width="2.5"'
                f' filter="url(#wt-soft-glow)" opacity="0"/>'
            )
            parts.append(
                f'<rect class="wt-cell-sel" x="{cx - 0.5:.1f}" y="{cy - 0.5:.1f}"'
                f' width="{g["cell_w"] + 1}" height="{g["cell_h"] + 1}"'
                f' rx="7.5" ry="7.5" fill="none" stroke="#cbd3dd"'
                f' stroke-width="0.8" opacity="0"/>'
            )
            parts.append("</g>")

    # Bottom time-axis hint — minimal, dim, non-shouty.
    axis_y = g["label_top"] + g["grid_h"] + 13
    axis_x_left = g["label_left"]
    axis_x_right = g["label_left"] + g["grid_w"]
    parts.append(
        f'<text x="{axis_x_left:.1f}" y="{axis_y:.1f}"'
        f' font-family="system-ui,-apple-system,sans-serif" font-size="8"'
        f' fill="#4a5563" letter-spacing="0.08em" style="text-transform:uppercase">'
        f'older</text>'
    )
    parts.append(
        f'<text x="{axis_x_right:.1f}" y="{axis_y:.1f}" text-anchor="end"'
        f' font-family="system-ui,-apple-system,sans-serif" font-size="8"'
        f' fill="#4a5563" letter-spacing="0.08em" style="text-transform:uppercase">'
        f'now</text>'
    )

    parts.append("</svg>")
    return "\n".join(parts)


def _build_matrix_overview_html(matrix_data: dict) -> str:
    """Right-rail Overview panel: ranked cells by max_risk, click to lock."""
    cells = matrix_data.get("cells", {})
    pt_labels = matrix_data.get("problem_type_labels", PROBLEM_TYPE_LABELS)
    af_labels = matrix_data.get("affects_labels", AFFECTS_LABELS)
    af_colors = matrix_data.get("affects_colors", AFFECTS_COLORS)
    if not cells:
        return (
            '<div class="muted" style="font-size:.78rem;padding:.4rem 0">'
            "No findings classified into matrix cells in this window.</div>"
        )
    rows: list[str] = []
    ranked = sorted(
        cells.items(),
        key=lambda kv: (
            kv[1].get("max_risk", 0),
            kv[1].get("active_count", 0),
            kv[1].get("p1_count", 0),
        ),
        reverse=True,
    )
    for cell_key, cell in ranked[:14]:
        pt, af = cell_key.split("|", 1)
        af_color = af_colors.get(af, "#94a3b8")
        max_risk = cell.get("max_risk", 0)
        active = cell.get("active_count", 0)
        p1 = cell.get("p1_count", 0)
        long_runner = cell.get("long_runner_count", 0)
        if active == 0 and long_runner == 0:
            continue
        bar_pct = max(2, min(100, max_risk))
        rows.append(
            f'<div class="wt-cell-rank" data-cell="{cell_key}" '
            f'onclick="wtSelectCell(\'{cell_key}\')">'
            f'<span class="wt-cell-rank-swatch" style="background:{af_color}"></span>'
            f'<span class="wt-cell-rank-label">{html.escape(pt_labels.get(pt, pt))}'
            f' · <span style="color:#7a8493">{html.escape(af_labels.get(af, af))}</span></span>'
            f'<span class="wt-cell-rank-bar"><span class="wt-cell-rank-fill" '
            f'style="width:{bar_pct}%;background:#7a8493"></span></span>'
            f'<span class="wt-cell-rank-meta">{active}'
            + (f' · <span style="color:#ef4444">P1·{p1}</span>' if p1 else "")
            + (f' · <span style="color:#7a8493">{long_runner}↻</span>' if long_runner else "")
            + "</span></div>"
        )
    if not rows:
        return (
            '<div class="muted" style="font-size:.78rem;padding:.4rem 0">'
            "All matrix cells are quiet right now.</div>"
        )
    return (
        '<div class="wt-cell-rank wt-cell-rank--all" '
        'onclick="wtSelectCell(\'all\')">'
        '<span class="wt-cell-rank-swatch" style="background:#3a3a3a"></span>'
        '<span class="wt-cell-rank-label" style="color:#c9d1d9;font-weight:700">All Cells</span>'
        '<span class="wt-cell-rank-bar"></span>'
        f'<span class="wt-cell-rank-meta" style="color:#c9d1d9;font-weight:700">'
        f'{sum(c.get("active_count", 0) for c in cells.values())}</span>'
        "</div>"
    ) + "".join(rows)


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


def _build_forensics_html(cards: list, ioc_ledger: dict = None, history_days: list = None) -> str:
    """Build the Forensics rail-tab content: CVE index, kill-chain breakdown,
    affected product matrix, IOC intelligence panel, and CVE timeline.

    All panels are generated from the current-window ``cards`` list,
    the cross-run ``ioc_ledger`` dict, and optionally ``history_days``
    (list of annotated day dicts, newest-first) for the CVE timeline.
    No network or model calls are made.
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

    # ── Panel E: CVE Timeline ──────────────────────────────────────────────────────────────
    cve_timeline_html = ""
    if history_days:
        # Build per-CVE history: oldest → newest (history_days is newest-first, so reverse)
        _cve_hist: dict = {}  # cve -> {first_seen, days: {date_str: {patch_status, titles[]}}}
        for day in reversed(history_days):
            date_str = day.get("date_str", "")
            for card in day.get("cards", []):
                cves = (card.get("enrichment") or {}).get("cves") or []
                ps = card.get("patch_status", "unknown")
                title = card.get("title", "")
                for cve in cves:
                    if cve not in _cve_hist:
                        _cve_hist[cve] = {"first_seen": date_str, "days": {}}
                    day_entry = _cve_hist[cve]["days"].setdefault(
                        date_str, {"patch_status": "unknown", "titles": []}
                    )
                    # Keep highest-ranked patch status for this day
                    if _PATCH_RANK.get(ps, 0) > _PATCH_RANK.get(day_entry["patch_status"], 0):
                        day_entry["patch_status"] = ps
                    if title and title not in day_entry["titles"]:
                        day_entry["titles"].append(title)

        # Only render CVEs with 2+ history days or present in current window
        current_cves = set(cve_map.keys())
        tl_rows = []
        for cve, data in sorted(
            _cve_hist.items(),
            key=lambda x: (len(x[1]["days"]), x[0]),
            reverse=True,
        )[:25]:
            n_days = len(data["days"])
            if n_days < 2 and cve not in current_cves:
                continue
            # Determine current patch status
            cur_status = (
                cve_map[cve]["patch_status"]
                if cve in cve_map
                else data["days"][max(data["days"].keys())]["patch_status"]
            )
            lbl, col = _PATCH_LABELS.get(cur_status, ("? Unknown", "#8b949e"))
            esc = html.escape(cve)
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{esc}"

            # Compact patch progression: only emit entries where status changes
            prog_parts = []
            prev_ps = None
            for d_str, d_data in sorted(data["days"].items()):
                ps2 = d_data["patch_status"]
                if ps2 != prev_ps:
                    lbl2, col2 = _PATCH_LABELS.get(ps2, ("? Unknown", "#8b949e"))
                    d_short = d_str[5:]  # MM-DD
                    prog_parts.append(
                        f'<span style="color:{col2};font-size:.67rem">{d_short}: {lbl2}</span>'
                    )
                    prev_ps = ps2
            prog_html = (
                '<div class="cve-tl-prog">'
                + ' <span style="color:#555">→</span> '.join(prog_parts)
                + "</div>"
                if len(prog_parts) > 1
                else ""
            )

            # Per-day finding references
            day_refs_html = ""
            for d_str, d_data in sorted(data["days"].items()):
                titles = d_data["titles"]
                if not titles:
                    continue
                shown = titles[:3]
                extra = len(titles) - 3
                day_refs_html += (
                    '<div style="margin:.18rem 0;font-size:.69rem">'
                    + f'<span style="color:#6a7f98;font-family:monospace">{d_str}</span> '
                    + " · ".join(html.escape(t[:65]) for t in shown)
                    + (
                        f' <span style="color:#555">+{extra} more</span>'
                        if extra > 0
                        else ""
                    )
                    + "</div>"
                )

            tl_rows.append(
                '<details class="forensics-acc">'
                + "<summary>"
                + '<a href="'
                + nvd_url
                + '" target="_blank" rel="noopener noreferrer"'
                + ' style="color:#79c0ff;font-family:monospace;font-size:.78rem"'
                + ' onclick="event.stopPropagation()">'
                + esc
                + "</a>"
                + f'<span style="color:#8b949e;font-size:.68rem;margin-left:.4rem">'
                + f"{n_days}d tracked</span>"
                + f'<span style="color:{col};font-size:.7rem;margin-left:.4rem">{lbl}</span>'
                + "</summary>"
                + '<div style="padding:.2rem .5rem .3rem">'
                + prog_html
                + day_refs_html
                + "</div></details>"
            )

        if tl_rows:
            cve_timeline_html = (
                '<h4 class="forensics-section-title">CVE Timeline</h4>'
                '<p class="forensics-hint">Patch status progression and finding references'
                " from the past 7 days. Expand a row for day-by-day detail.</p>"
                + "".join(tl_rows)
            )
        else:
            cve_timeline_html = (
                '<h4 class="forensics-section-title">CVE Timeline</h4>'
                '<div class="forensics-empty">No cross-run CVE history available yet.</div>'
            )

    return cve_html + killchain_html + product_html + ioc_html + cve_timeline_html


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


def _build_breach_strip_html(breaches: list) -> str:
    """Phase 7 — breach strip rendered above the matrix.

    Distinct visual class from CVE bubbles (square chips, different verb)
    because the user action ("rotate" / "close" / "monitor") differs from
    "patch" / "isolate".  Empty list renders as nothing.
    """
    from agent.breach import format_count

    if not breaches:
        return ""
    items: list[str] = []
    for b in breaches:
        action = (b.get("action", "monitor") or "monitor").lower()
        action_labels = {
            "rotate": "rotate now",
            "close": "close / freeze account",
            "monitor": "monitor for misuse",
        }
        action_label = action_labels.get(action, "review")
        action_class = f"wt-breach-action--{action}"
        count_str = format_count(b.get("affected_count", 0))
        date_str = b.get("date") or b.get("added") or ""
        title = b.get("title") or b.get("name") or "Untitled breach"
        url = b.get("source_url", "")
        items.append(
            f'<a class="wt-breach-item" href="{html.escape(url)}"'
            f' target="_blank" rel="noopener noreferrer"'
            f' data-breach-id="{html.escape(b.get("id", ""))}">'
            f'<span class="wt-breach-glyph">▣</span>'
            f'<span class="wt-breach-body">'
            f'<span class="wt-breach-title">{html.escape(title)}</span>'
            f'<span class="wt-breach-meta">'
            + (f'<span class="wt-breach-date">{html.escape(date_str)}</span>' if date_str else "")
            + (f'<span class="wt-breach-count">{count_str} affected</span>' if count_str else "")
            + f'<span class="wt-breach-action {action_class}">{action_label}</span>'
            + "</span></span></a>"
        )
    return (
        '<section class="wt-breach-strip">'
        '<div class="wt-breach-strip-header">'
        '<span class="wt-breach-strip-title">Was your data exposed?</span>'
        f'<span class="wt-breach-strip-count">{len(breaches)} recent breach{"es" if len(breaches) != 1 else ""}</span>'
        "</div>"
        '<div class="wt-breach-strip-body">'
        + "".join(items)
        + "</div></section>"
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
    feed_health: dict = None,
    run_metrics: dict = None,
    feed_run_metrics: dict = None,
    velocity: dict = None,
    ioc_ledger: dict = None,
    breaches: list = None,
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

    breach_strip_html = _build_breach_strip_html(breaches or [])
    matrix_data = build_matrix_data(cards)
    # Trajectory series for the watermark (Phase 6).  Reads briefing JSONL archive
    # plus the current run's cards; window covers max slider value (180d).
    try:
        import os as _os
        from agent.state import load_json as _load_json
        from agent.trajectory import build_trajectory as _build_trajectory

        _root = _os.path.dirname(_os.path.dirname(__file__))
        _reports = _os.path.join(_root, "reports")
        _shelf = _load_json(_os.path.join(_root, "state", "finding_shelf.json"), {})
        matrix_data["trajectory"] = _build_trajectory(
            cards, _reports, _shelf, window_days=180
        )
    except Exception as _exc:
        # Trajectory is decorative; never block the page render
        print(f"[WARN] trajectory build failed: {_exc}")
        matrix_data["trajectory"] = {}
    threat_svg = _build_threat_matrix_svg(matrix_data)
    domain_rank_html = _build_matrix_overview_html(matrix_data)

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
                        <button class="rem-pill" data-card-id="{html.escape(c.get('id', ''))}" title="Remediation: Unacknowledged" onclick="event.stopPropagation();remCycle(this)">\u2299</button>
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
        _epss = c.get("epss_score")
        try:
            _epss = float(_epss) if _epss is not None else None
        except (TypeError, ValueError):
            _epss = None
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
                "problem_type": c.get("problem_type", ""),
                "affects": c.get("affects", ""),
                "classification_confidence": float(c.get("classification_confidence", 1.0) or 1.0),
                "classification_reasoning": c.get("classification_reasoning", "") or "",
                "cross_cutting": list(c.get("cross_cutting") or []),
                "is_kev": bool(c.get("is_kev")),
                "epss_score": _epss,
            }
        )

    forensics_html = _build_forensics_html(cards, ioc_ledger or {}, history_days)
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
.wt-cell{{transition:filter .18s ease,transform .18s ease}}
.wt-cell:not(.wt-cell--empty):hover{{filter:brightness(1.18) saturate(1.1)}}
.wt-cell:not(.wt-cell--empty):hover .wt-cell-bg{{fill-opacity:1!important}}
.wt-cell--empty{{opacity:.62}}
.wt-cell--empty:hover{{opacity:.85}}
.wt-cell--locked .wt-cell-sel,.wt-cell--locked .wt-cell-sel-glow{{opacity:1}}
.wt-cell--locked .wt-cell-bg{{filter:brightness(1.45) saturate(1.1)}}
.wt-cell--collapsed{{transform:scaleY(0.12);transform-origin:left center;opacity:0.45}}
.wt-cell-kev-dot{{animation:wt-kev-pulse 2.4s ease-in-out infinite}}
@keyframes wt-kev-pulse{{0%,100%{{opacity:0.5;r:2.0}}50%{{opacity:1;r:2.6}}}}
.wt-row-label:hover text{{fill:#dbe2ec}}
.wt-row-label:hover rect{{opacity:1}}
.wt-bubble{{transition:transform .15s ease,filter .15s ease}}
.wt-bubble:hover{{filter:brightness(1.6) drop-shadow(0 0 4px rgba(255,255,255,.4))}}
.wt-bubble--low-conf circle{{stroke-dasharray:1.6 1.4}}
.wt-bubble--long-runner .wt-bubble-ring{{stroke:#94a3b8;stroke-opacity:.85;stroke-width:1.2}}
.wt-bubble--urgent .wt-bubble-halo{{animation:wt-urgent-pulse 1.6s ease-in-out infinite}}
.wt-bubble--moved .wt-bubble-moved-badge{{opacity:1}}
.wt-bubble--locked .wt-bubble-lock-ring{{opacity:1;stroke:#e6edf3;stroke-width:1.4;fill:none}}
@keyframes wt-urgent-pulse{{0%,100%{{opacity:.35;transform:scale(1)}}50%{{opacity:.85;transform:scale(1.18)}}}}
.wt-cross-line{{stroke:#e6edf3;stroke-opacity:.55;stroke-dasharray:2.5 2}}
.wt-slider{{display:flex;align-items:center;gap:.35rem;padding:.4rem .35rem .55rem;flex-wrap:wrap}}
.wt-slider-label{{font-size:.66rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700;margin-right:.25rem}}
.wt-slider-btn{{background:#181818;border:1px solid #2a2a2a;color:#8b949e;font-size:.7rem;font-weight:600;padding:.22rem .65rem;border-radius:999px;cursor:pointer;letter-spacing:.02em;transition:background .12s,color .12s,border-color .12s}}
.wt-slider-btn:hover{{background:#252525;color:#c9d1d9}}
.wt-slider-btn[aria-pressed="true"]{{background:rgba(58,130,246,.16);border-color:rgba(58,130,246,.4);color:#79b8ff}}
.wt-slider-hint{{font-size:.66rem;color:#5a6a7a;font-style:italic;margin-left:.4rem;transition:opacity .4s}}
.wt-slider-hint.wt-fading{{opacity:0}}
.wt-slider-hint.wt-hidden{{display:none}}
.wt-cell--collapsed rect:first-of-type{{height:6px!important;opacity:.35}}
.wt-cell--collapsed text{{display:none}}
.wt-cell-pin{{font-size:7px;font-weight:700;fill:#94a3b8}}
.wt-breach-strip{{background:#241612;border:1px solid #4a2419;border-radius:8px;padding:.55rem .85rem .65rem;margin:0 0 .9rem}}
.wt-breach-strip-header{{display:flex;align-items:center;gap:.5rem;margin-bottom:.45rem}}
.wt-breach-strip-title{{font-size:.78rem;font-weight:700;color:#f9b29c;text-transform:uppercase;letter-spacing:.06em}}
.wt-breach-strip-count{{font-size:.66rem;color:#c97a6a;font-weight:600;background:rgba(249,178,156,.1);border:1px solid rgba(249,178,156,.25);border-radius:999px;padding:1px 8px}}
.wt-breach-strip-body{{display:flex;flex-direction:column;gap:.32rem}}
.wt-breach-item{{display:flex;align-items:center;gap:.55rem;padding:.4rem .55rem;background:#1a0f0c;border:1px solid #3a1f17;border-radius:5px;text-decoration:none;color:inherit;transition:background .12s,border-color .12s}}
.wt-breach-item:hover{{background:#251411;border-color:#5a2c20}}
.wt-breach-glyph{{flex-shrink:0;font-size:1rem;color:#f9b29c;font-weight:700;line-height:1}}
.wt-breach-body{{display:flex;flex-direction:column;gap:.18rem;flex:1;overflow:hidden}}
.wt-breach-title{{font-size:.82rem;color:#f5d5cb;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.wt-breach-meta{{display:flex;flex-wrap:wrap;gap:.35rem;font-size:.66rem;color:#a8867f}}
.wt-breach-date{{color:#a8867f}}
.wt-breach-count{{color:#d4a89e;font-weight:600}}
.wt-breach-action{{font-weight:700;letter-spacing:.04em;text-transform:uppercase;border-radius:3px;padding:1px 6px}}
.wt-breach-action--rotate{{background:rgba(248,113,113,.12);color:#fca5a5;border:1px solid rgba(248,113,113,.3)}}
.wt-breach-action--close{{background:rgba(252,165,165,.08);color:#f87171;border:1px solid rgba(252,165,165,.25)}}
.wt-breach-action--monitor{{background:rgba(245,158,11,.1);color:#fbbf24;border:1px solid rgba(245,158,11,.28)}}
.wt-cell:focus,.wt-bubble:focus{{outline:2px solid #79b8ff;outline-offset:2px}}
@media print{{
  body{{background:#fff;color:#111}}
  .right-rail,.rail-mobile-toggle,.rail-backdrop,.findings-filter,.tactic-strip,.wt-slider,.run-metrics-bar,.delta-strip,.next-run,#rail-mobile-toggle{{display:none!important}}
  .header-bar{{position:static;background:#fff;border-bottom:1px solid #aaa}}
  .app-shell{{padding-top:0}}
  .app-main{{padding:0!important}}
  .panel,.executive,.weekly-scope,.threat-section{{break-inside:avoid;page-break-inside:avoid;border-color:#bbb;background:#fff;color:#111}}
  .threat-title,h1,h2,h3{{color:#111!important}}
  .wt-cell rect:first-of-type{{fill:#ddd!important;stroke:#999!important}}
  .wt-bubble circle{{stroke:#333!important}}
  .wt-breach-strip{{background:#fff;border-color:#bbb}}
  .wt-breach-strip-title,.wt-breach-title{{color:#111!important}}
  a{{color:#0366d6!important}}
}}
.wt-cell-rank{{display:flex;align-items:center;gap:.45rem;padding:.32rem .3rem;border-radius:4px;cursor:pointer;font-size:.74rem}}
.wt-cell-rank:hover{{background:rgba(255,255,255,.04)}}
.wt-cell-rank--all{{border-bottom:1px solid #252525;margin-bottom:.35rem;padding-bottom:.45rem}}
.wt-cell-rank-swatch{{flex-shrink:0;width:3px;height:14px;border-radius:2px}}
.wt-cell-rank-label{{flex:1;color:#c9d1d9;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.wt-cell-rank-bar{{flex:0 0 70px;height:3px;background:#181818;border-radius:2px;overflow:hidden}}
.wt-cell-rank-fill{{display:block;height:3px;border-radius:2px}}
.wt-cell-rank-meta{{flex:0 0 auto;font-size:.68rem;color:#8b949e;font-weight:600;letter-spacing:.02em}}
.wt-tooltip{{position:fixed;z-index:50;background:#0a0a0a;border:1px solid #3a3a3a;border-radius:5px;padding:.45rem .6rem;color:#c9d1d9;font-size:.72rem;line-height:1.4;max-width:320px;pointer-events:none;box-shadow:0 4px 12px rgba(0,0,0,.5)}}
.wt-tooltip strong{{color:#e6edf3;display:block;margin-bottom:.2rem;font-size:.78rem}}
.wt-tooltip .wt-tt-meta{{color:#8b949e;font-size:.66rem;margin-bottom:.25rem}}
.wt-tooltip .wt-tt-reason{{color:#79b8ff;font-size:.66rem;font-style:italic;margin-top:.22rem;border-top:1px solid #1f1f1f;padding-top:.22rem}}
.wt-detail-finding{{display:block;margin:.45rem 0;padding:.45rem .55rem;border-left:2px solid #2a2a2a;border-radius:0 4px 4px 0;background:rgba(255,255,255,.015);cursor:pointer}}
.wt-detail-finding:hover{{background:rgba(255,255,255,.04)}}
.wt-detail-finding .wt-df-title{{display:block;color:#c9d1d9;font-size:.78rem;font-weight:500;margin-bottom:.2rem}}
.wt-detail-finding .wt-df-meta{{display:block;color:#8b949e;font-size:.66rem;margin-bottom:.2rem}}
.wt-detail-finding .wt-df-summary{{display:block;color:#7a8b9a;font-size:.7rem;line-height:1.4;max-height:3.5em;overflow:hidden}}
.wt-detail-finding .wt-df-reason{{display:block;color:#79b8ff;font-size:.65rem;font-style:italic;margin-top:.25rem;border-top:1px solid #1f1f1f;padding-top:.2rem}}
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
.rem-pill{{background:none;border:1px solid #333;border-radius:3px;color:#555;cursor:pointer;font-size:.62rem;padding:1px 5px;margin-left:.3rem;flex-shrink:0;vertical-align:middle;line-height:1.4;transition:border-color .12s,color .12s}}
.rem-pill:hover{{border-color:#666;color:#8b949e}}
.cluster[data-rem-state="inprog"] .rem-pill{{border-color:#f9c74f;color:#f9c74f}}
.cluster[data-rem-state="accepted"] .rem-pill{{border-color:#8b949e;color:#8b949e}}
.cluster[data-rem-state="mitigated"] .rem-pill{{border-color:#3fb950;color:#3fb950}}
.cluster[data-rem-state="mitigated"]{{opacity:.38;filter:grayscale(.6)}}
.cve-tl-prog{{display:flex;flex-wrap:wrap;gap:.25rem .3rem;margin-bottom:.2rem;align-items:center}}
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
{breach_strip_html}
<section class="threat-section" id="wt-app">
  <div class="panel threat-main">
    <div class="threat-toolbar">
      <div>
        <div class="threat-title">Threat Matrix</div>
        <div class="threat-sub">Findings classified by <strong>problem type × what it affects</strong>. Each cell holds individual findings. Click a cell to lock the side panel; hover any bubble for context.</div>
      </div>
      <span class="chip" title="Data polled from the last {since_hours} hours">{_window_chip}</span>
    </div>
    <div class="wt-slider" id="wt-slider" role="radiogroup" aria-label="Time window">
      <span class="wt-slider-label">Window:</span>
      <button type="button" class="wt-slider-btn" data-window="7" aria-pressed="false">7d</button>
      <button type="button" class="wt-slider-btn" data-window="30" aria-pressed="true">30d</button>
      <button type="button" class="wt-slider-btn" data-window="90" aria-pressed="false">90d</button>
      <button type="button" class="wt-slider-btn" data-window="180" aria-pressed="false">180d</button>
      <button type="button" class="wt-slider-btn" data-window="99999" aria-pressed="false">all</button>
      <span class="wt-slider-hint" id="wt-slider-hint">drag to widen or narrow</span>
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
                            <h3 style="margin:.2rem 0 .35rem">Top Cells</h3>
                            {domain_rank_html}
                            <h3 style="margin:.7rem 0 .35rem" id="wt-detail-heading">Selected Cell</h3>
                            <div id="tm-detail" class="muted" style="font-size:.8rem">Click any matrix cell to inspect its findings, or click a bubble to lock on a single finding.</div>
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
var WT_DATA={json.dumps(matrix_data)};
var WT_CARDS_BY_ID=(function(){{var m={{}};(CARDS||[]).forEach(function(c){{if(c&&c.id)m[c.id]=c;}});return m;}})();
var WT_CURRENT_CELL='all';
var WT_LOCKED_FINDING=null;
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

// ──────────────────────────────────────────────
// Threat matrix client-side behavior (Phase 2-4)
// Renders bubbles, hover tooltips, click-lock side panel.
// ──────────────────────────────────────────────
function wtCellGeometry(){{
  return {{cellW:88,cellH:64,gutterX:6,gutterY:6,labelLeft:110,labelTop:28,margin:8}};
}}
function wtCellOrigin(ci,ri){{
  var g=wtCellGeometry();
  return {{x:g.labelLeft+ci*(g.cellW+g.gutterX), y:g.labelTop+ri*(g.cellH+g.gutterY)}};
}}
function wtBubbleRadius(score){{
  var s=Math.max(1,score|0);
  return Math.max(2.0,Math.min(9.0,1.4*Math.log(s+1)+1.6));
}}

function wtFormatAge(days){{
  if(!isFinite(days)||days<0) return '';
  if(days<1){{var h=Math.max(1,Math.round(days*24));return h+'h';}}
  if(days<60) return Math.round(days)+'d';
  return Math.round(days/30)+'mo';
}}

function wtRenderBubbles(){{
  var data=WT_DATA||{{}};
  var bubbles=data.bubbles||[];
  var pts=data.problem_types||[];
  var afs=data.affects||[];
  var ptIdx={{}}, afIdx={{}};
  pts.forEach(function(p,i){{ptIdx[p]=i;}});
  afs.forEach(function(a,i){{afIdx[a]=i;}});

  // Group bubbles by cell
  var byCell={{}};
  bubbles.forEach(function(b){{
    if(!byCell[b.cell]) byCell[b.cell]=[];
    byCell[b.cell].push(b);
  }});

  // Determine the time horizon (max age in current data, capped at 90d for Phase 2).
  // Phase 5 will replace this with a slider value.
  var maxAge=0;
  bubbles.forEach(function(b){{ if((b.age_days||0)>maxAge) maxAge=b.age_days||0; }});
  if(maxAge<7) maxAge=7;
  if(maxAge>90) maxAge=90;

  var g=wtCellGeometry();
  var padX=8, padY=8;
  var innerW=g.cellW-2*padX, innerH=g.cellH-2*padY;

  Object.keys(byCell).forEach(function(cellKey){{
    var layer=document.querySelector('.wt-bubble-layer[data-cell="'+cellKey+'"]');
    if(!layer) return;
    layer.innerHTML='';
    var list=byCell[cellKey].slice();
    // Sort by risk desc so bigger bubbles render last (on top)
    list.sort(function(a,b){{return(a.risk_score||0)-(b.risk_score||0);}});
    // Position with simple jitter to avoid stacking
    list.forEach(function(b,idx){{
      var ageRatio=Math.max(0,Math.min(1,1-((b.age_days||0)/maxAge)));
      var riskRatio=Math.max(0,Math.min(1,(b.risk_score||0)/100));
      var bx=padX + ageRatio*innerW;
      var by=padY + (1-riskRatio)*innerH;
      // Tiny jitter — derived from id so it's stable across renders
      var seed=0;
      for(var i=0;i<(b.id||'').length;i++) seed=(seed*31+(b.id.charCodeAt(i)))&0xffff;
      var jx=((seed%7)-3)*0.6, jy=(((seed>>3)%7)-3)*0.6;
      bx=Math.max(padX-2,Math.min(g.cellW-padX+2,bx+jx));
      by=Math.max(padY-2,Math.min(g.cellH-padY+2,by+jy));
      var r=wtBubbleRadius(b.risk_score);

      var classes=['wt-bubble'];
      if(b.is_kev||(b.epss!==null&&b.epss!==undefined&&b.epss>=0.7)) classes.push('wt-bubble--urgent');
      if(b.is_low_confidence) classes.push('wt-bubble--low-conf');
      if(b.is_long_runner) classes.push('wt-bubble--long-runner');
      if(b.is_resolved) classes.push('wt-bubble--resolved');
      if(b.recategorized_within_24h) classes.push('wt-bubble--moved');

      var color=b.priority==='P1' ? '#f87171' : b.priority==='P2' ? '#f59e0b' : '#79b8ff';
      var stroke=b.is_kev?'#fca5a5':color;

      var ns='http://www.w3.org/2000/svg';
      var grp=document.createElementNS(ns,'g');
      grp.setAttribute('class',classes.join(' '));
      grp.setAttribute('data-finding-id',b.id);
      grp.setAttribute('transform','translate('+bx.toFixed(2)+','+by.toFixed(2)+')');
      grp.style.cursor='pointer';

      // Halo (urgent pulse target)
      if(classes.indexOf('wt-bubble--urgent')>=0){{
        var halo=document.createElementNS(ns,'circle');
        halo.setAttribute('class','wt-bubble-halo');
        halo.setAttribute('r',(r+3.5).toFixed(2));
        halo.setAttribute('fill',stroke);
        halo.setAttribute('opacity','0.4');
        grp.appendChild(halo);
      }}
      // Long-runner outer ring + Nd label
      if(classes.indexOf('wt-bubble--long-runner')>=0){{
        var ring=document.createElementNS(ns,'circle');
        ring.setAttribute('class','wt-bubble-ring');
        ring.setAttribute('r',(r+1.8).toFixed(2));
        ring.setAttribute('fill','none');
        ring.setAttribute('stroke','#94a3b8');
        ring.setAttribute('stroke-width','1.0');
        ring.setAttribute('opacity','0.7');
        grp.appendChild(ring);
        if((b.shelf_days||0)>=1){{
          var lbl=document.createElementNS(ns,'text');
          lbl.setAttribute('class','wt-bubble-runner-label');
          lbl.setAttribute('x','0');
          lbl.setAttribute('y',(r+8.5).toFixed(2));
          lbl.setAttribute('text-anchor','middle');
          lbl.setAttribute('font-family','system-ui,sans-serif');
          lbl.setAttribute('font-size','7');
          lbl.setAttribute('font-weight','700');
          lbl.setAttribute('fill','#94a3b8');
          lbl.setAttribute('opacity','0.85');
          lbl.textContent=b.shelf_days+'d';
          grp.appendChild(lbl);
        }}
      }}
      // Lock ring (visible only when locked)
      var lockRing=document.createElementNS(ns,'circle');
      lockRing.setAttribute('class','wt-bubble-lock-ring');
      lockRing.setAttribute('r',(r+3).toFixed(2));
      lockRing.setAttribute('fill','none');
      lockRing.setAttribute('stroke','#e6edf3');
      lockRing.setAttribute('stroke-width','0');
      lockRing.setAttribute('opacity','0');
      grp.appendChild(lockRing);
      // Body
      var body=document.createElementNS(ns,'circle');
      body.setAttribute('r',r.toFixed(2));
      body.setAttribute('fill',color);
      body.setAttribute('fill-opacity', b.is_resolved?'0.35':'0.85');
      body.setAttribute('stroke',stroke);
      body.setAttribute('stroke-opacity', b.is_resolved?'0.45':'0.95');
      body.setAttribute('stroke-width', b.is_low_confidence?'1.2':'0.8');
      grp.appendChild(body);
      // Recategorized badge (Phase 9 sets this; benign no-op now)
      if(classes.indexOf('wt-bubble--moved')>=0){{
        var badge=document.createElementNS(ns,'text');
        badge.setAttribute('class','wt-bubble-moved-badge');
        badge.setAttribute('x',(r+1.5).toFixed(2));
        badge.setAttribute('y',(-r).toFixed(2));
        badge.setAttribute('font-size','7');
        badge.setAttribute('fill','#79b8ff');
        badge.setAttribute('font-family','system-ui,sans-serif');
        badge.setAttribute('opacity','0');
        badge.textContent='↻';
        grp.appendChild(badge);
      }}
      grp.addEventListener('mouseenter',function(){{
        wtShowTooltip(b,grp);
        // Hover-draws cross-cutting lines so the relationship is revealed
        // on intent rather than baked into the visual. Stays on click-lock.
        var card=WT_CARDS_BY_ID[b.id];
        if(card&&Array.isArray(card.cross_cutting)&&card.cross_cutting.length){{
          wtClearCrossCuttingLines();
          wtDrawCrossCuttingLines(card,b.id);
        }}
      }});
      grp.addEventListener('mouseleave',function(){{
        wtHideTooltip();
        // Only clear hover-drawn lines if no finding is locked — locked
        // finding keeps its relationship visible.
        if(!WT_LOCKED_FINDING) wtClearCrossCuttingLines();
        else if(WT_LOCKED_FINDING!==b.id){{
          // Restore lock-state lines
          var lc=WT_CARDS_BY_ID[WT_LOCKED_FINDING];
          if(lc&&Array.isArray(lc.cross_cutting)){{
            wtClearCrossCuttingLines();
            wtDrawCrossCuttingLines(lc,WT_LOCKED_FINDING);
          }}
        }}
      }});
      grp.addEventListener('mousemove',function(e){{wtMoveTooltip(e);}});
      grp.addEventListener('click',function(e){{
        e.stopPropagation();
        wtSelectFinding(b.id);
      }});
      layer.appendChild(grp);
    }});
  }});
}}

var WT_TT_EL=null;
function wtEnsureTooltip(){{
  if(WT_TT_EL) return WT_TT_EL;
  WT_TT_EL=document.createElement('div');
  WT_TT_EL.className='wt-tooltip';
  WT_TT_EL.style.opacity='0';
  WT_TT_EL.style.transition='opacity .12s';
  document.body.appendChild(WT_TT_EL);
  return WT_TT_EL;
}}
function wtShowTooltip(b){{
  var el=wtEnsureTooltip();
  var card=WT_CARDS_BY_ID[b.id]||{{}};
  var meta=[];
  if(b.priority) meta.push(b.priority);
  if(b.risk_score) meta.push('risk '+b.risk_score);
  if(b.is_kev) meta.push('KEV');
  if(b.epss!==null&&b.epss!==undefined) meta.push('EPSS '+(Math.round(b.epss*100))+'%');
  if(b.age_days>=0) meta.push(wtFormatAge(b.age_days)+' old');
  if(b.is_long_runner) meta.push(b.shelf_days+'d unresolved');
  if(b.is_resolved) meta.push('resolved');
  var reason=b.classification_reasoning||card.classification_reasoning||'';
  var conf=card.classification_confidence;
  el.innerHTML='<strong>'+(b.title||card.title||'')+'</strong>'
    +'<div class="wt-tt-meta">'+meta.join(' · ')+'</div>'
    +(reason?'<div class="wt-tt-reason">Groq: '+reason+(conf!==undefined?' (conf '+(Number(conf).toFixed(2))+')':'')+'</div>':'');
  el.style.opacity='1';
}}
function wtHideTooltip(){{
  if(WT_TT_EL) WT_TT_EL.style.opacity='0';
}}
function wtMoveTooltip(e){{
  if(!WT_TT_EL) return;
  var x=e.clientX+14, y=e.clientY+12;
  var rect=WT_TT_EL.getBoundingClientRect();
  if(x+rect.width>window.innerWidth-8) x=e.clientX-rect.width-14;
  if(y+rect.height>window.innerHeight-8) y=e.clientY-rect.height-12;
  WT_TT_EL.style.left=x+'px';
  WT_TT_EL.style.top=y+'px';
}}

function wtRenderCellDetail(cellKey){{
  var data=WT_DATA||{{}};
  var cells=data.cells||{{}};
  var ptLabels=data.problem_type_labels||{{}};
  var afLabels=data.affects_labels||{{}};
  var t=document.getElementById('tm-detail');
  var heading=document.getElementById('wt-detail-heading');
  if(!t) return;
  if(!cellKey||cellKey==='all'){{
    if(heading) heading.textContent='Selected Cell';
    t.innerHTML='Click any matrix cell to inspect its findings, or click a bubble to lock on a single finding.';
    return;
  }}
  var parts=cellKey.split('|');
  var pt=parts[0], af=parts[1];
  var cell=cells[cellKey];
  if(!cell||(!cell.findings||!cell.findings.length)){{
    if(heading) heading.textContent=ptLabels[pt]+' × '+afLabels[af];
    t.innerHTML='<div style="color:#5a7090;font-size:.78rem">No active findings in this cell.</div>';
    return;
  }}
  if(heading) heading.textContent=ptLabels[pt]+' × '+afLabels[af];
  var rows=cell.findings.map(function(fid){{
    var c=WT_CARDS_BY_ID[fid];
    if(!c) return '';
    var meta=[];
    if(c.priority) meta.push('<span style="color:'+(c.priority==='P1'?'#f87171':'#aaa')+';font-weight:700">'+c.priority+'</span>');
    if(c.risk_score) meta.push('risk '+c.risk_score);
    if(c.is_kev) meta.push('<span style="color:#fca5a5">KEV</span>');
    if(c.shelf_days&&!c.shelf_resolved&&c.shelf_days>7) meta.push('<span style="color:#94a3b8">'+c.shelf_days+'d open</span>');
    if(c.shelf_resolved) meta.push('<span style="color:#3fb950">resolved</span>');
    var reason=c.classification_reasoning||'';
    var conf=c.classification_confidence;
    return '<div class="wt-detail-finding" onclick="wtSelectFinding(\\''+c.id+'\\')">'
      +'<span class="wt-df-title">'+(c.title||'')+'</span>'
      +'<span class="wt-df-meta">'+meta.join(' · ')+'</span>'
      +(c.summary?'<span class="wt-df-summary">'+c.summary.slice(0,180)+(c.summary.length>180?'…':'')+'</span>':'')
      +(reason?'<span class="wt-df-reason">Groq: '+reason+(conf!==undefined?' (conf '+Number(conf).toFixed(2)+')':'')+'</span>':'')
      +'</div>';
  }}).join('');
  t.innerHTML='<div style="color:#8b949e;font-size:.7rem;margin-bottom:.4rem">'
    +cell.active_count+' active · max risk '+cell.max_risk
    +(cell.p1_count?' · P1 '+cell.p1_count:'')
    +(cell.long_runner_count?' · '+cell.long_runner_count+' ongoing':'')
    +'</div>'+rows;
}}

function wtRenderFindingDetail(findingId){{
  var c=WT_CARDS_BY_ID[findingId];
  var t=document.getElementById('tm-detail');
  var heading=document.getElementById('wt-detail-heading');
  if(!t||!c) return;
  if(heading) heading.textContent='Selected Finding';
  var meta=[];
  if(c.priority) meta.push('<span style="color:'+(c.priority==='P1'?'#f87171':'#aaa')+';font-weight:700">'+c.priority+'</span>');
  if(c.risk_score) meta.push('risk '+c.risk_score);
  if(c.is_kev) meta.push('<span style="color:#fca5a5">KEV</span>');
  if(c.epss_score!==null&&c.epss_score!==undefined) meta.push('EPSS '+Math.round(c.epss_score*100)+'%');
  if(c.shelf_days) meta.push(c.shelf_days+'d on shelf');
  if(c.shelf_resolved) meta.push('<span style="color:#3fb950">resolved</span>');
  var srcs=(c.sources||[]).map(function(s){{
    return '<a href="'+s.url+'" target="_blank" rel="noopener noreferrer" style="display:block;color:#79b8ff;font-size:.7rem;margin:.15rem 0">↗ '+s.title+'</a>';
  }}).join('');
  var actions=(c.actions_24h||[]).map(function(a){{return '<li style="margin:.1rem 0;font-size:.72rem;color:#c9d1d9">'+a+'</li>';}}).join('');
  var reason=c.classification_reasoning||'';
  t.innerHTML=
    '<div style="color:#e6edf3;font-size:.85rem;font-weight:600;margin-bottom:.35rem">'+c.title+'</div>'
    +'<div style="color:#8b949e;font-size:.7rem;margin-bottom:.4rem">'+meta.join(' · ')+'</div>'
    +(c.summary?'<p style="color:#c9d1d9;font-size:.78rem;line-height:1.45;margin:.2rem 0 .4rem">'+c.summary+'</p>':'')
    +(reason?'<div style="color:#79b8ff;font-size:.68rem;font-style:italic;margin:.25rem 0;padding:.25rem .4rem;background:rgba(121,184,255,.06);border-radius:3px">Groq classification: '+reason+'</div>':'')
    +(actions?'<div style="margin:.4rem 0 .25rem"><span style="font-size:.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700">Next 24h</span><ul style="margin:.2rem 0 .2rem 1rem;padding:0">'+actions+'</ul></div>':'')
    +(srcs?'<div style="margin-top:.4rem"><span style="font-size:.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700">Sources</span>'+srcs+'</div>':'');
}}

function wtSelectCell(cellKey){{
  WT_CURRENT_CELL=cellKey||'all';
  WT_LOCKED_FINDING=null;
  // Update visual lock state on cells
  document.querySelectorAll('.wt-cell').forEach(function(g){{
    var k=g.getAttribute('data-cell');
    g.classList.toggle('wt-cell--locked', WT_CURRENT_CELL!=='all' && k===WT_CURRENT_CELL);
  }});
  // Clear bubble lock state
  document.querySelectorAll('.wt-bubble--locked').forEach(function(g){{
    g.classList.remove('wt-bubble--locked');
  }});
  // Update findings cluster filter
  document.querySelectorAll('.cluster').forEach(function(el){{
    if(WT_CURRENT_CELL==='all'){{el.style.display='block';return;}}
    var ids=cellKey.split('|');
    var pt=ids[0], af=ids[1];
    var cardId=(el.id||'').replace(/^card-/,'');
    var c=WT_CARDS_BY_ID[cardId];
    var match=c&&c.problem_type===pt&&c.affects===af;
    if(!match&&c&&Array.isArray(c.cross_cutting)){{
      match=c.cross_cutting.indexOf(cellKey)>=0;
    }}
    el.style.display=match?'block':'none';
  }});
  wtRenderCellDetail(WT_CURRENT_CELL);
  trackUi('wt_cell_selected',{{cell:WT_CURRENT_CELL}});
}}

function wtSelectFinding(findingId){{
  if(!findingId){{wtSelectCell('all');return;}}
  WT_LOCKED_FINDING=findingId;
  var c=WT_CARDS_BY_ID[findingId];
  if(c&&c.problem_type&&c.affects){{
    WT_CURRENT_CELL=c.problem_type+'|'+c.affects;
  }}
  // Highlight bubbles
  document.querySelectorAll('.wt-bubble').forEach(function(g){{
    var locked=g.getAttribute('data-finding-id')===findingId;
    g.classList.toggle('wt-bubble--locked', locked);
    var ring=g.querySelector('.wt-bubble-lock-ring');
    if(ring) ring.setAttribute('stroke-width', locked?'1.4':'0');
  }});
  // Highlight current cell
  document.querySelectorAll('.wt-cell').forEach(function(g){{
    g.classList.toggle('wt-cell--locked', g.getAttribute('data-cell')===WT_CURRENT_CELL);
  }});
  wtRenderFindingDetail(findingId);
  // Cross-cutting connecting lines (Phase 4)
  wtClearCrossCuttingLines();
  if(c&&Array.isArray(c.cross_cutting)) wtDrawCrossCuttingLines(c, findingId);
  trackUi('wt_finding_locked',{{id:findingId,cell:WT_CURRENT_CELL}});
}}

function wtClearCrossCuttingLines(){{
  var svg=document.getElementById('wt-matrix-svg');
  if(!svg) return;
  var existing=svg.querySelectorAll('.wt-cross-line');
  existing.forEach(function(n){{n.parentNode&&n.parentNode.removeChild(n);}});
}}
function wtDrawCrossCuttingLines(card, findingId){{
  var svg=document.getElementById('wt-matrix-svg');
  if(!svg||!card) return;
  var ns='http://www.w3.org/2000/svg';
  var primary=card.problem_type+'|'+card.affects;
  var srcLayer=svg.querySelector('.wt-bubble-layer[data-cell="'+primary+'"]');
  if(!srcLayer) return;
  var srcBubble=srcLayer.querySelector('[data-finding-id="'+findingId+'"]');
  if(!srcBubble) return;
  var srcTransform=srcBubble.getAttribute('transform')||'';
  var srcMatch=/translate\\(([-0-9.]+)[ ,]([-0-9.]+)\\)/.exec(srcTransform);
  var layerMatch=/translate\\(([-0-9.]+)[ ,]([-0-9.]+)\\)/.exec(srcLayer.getAttribute('transform')||'');
  if(!srcMatch||!layerMatch) return;
  var sx=parseFloat(layerMatch[1])+parseFloat(srcMatch[1]);
  var sy=parseFloat(layerMatch[2])+parseFloat(srcMatch[2]);
  (card.cross_cutting||[]).forEach(function(cellKey){{
    var dstLayer=svg.querySelector('.wt-bubble-layer[data-cell="'+cellKey+'"]');
    if(!dstLayer) return;
    var dstMatch=/translate\\(([-0-9.]+)[ ,]([-0-9.]+)\\)/.exec(dstLayer.getAttribute('transform')||'');
    if(!dstMatch) return;
    var g=wtCellGeometry();
    var dx=parseFloat(dstMatch[1])+g.cellW/2;
    var dy=parseFloat(dstMatch[2])+g.cellH/2;
    var line=document.createElementNS(ns,'line');
    line.setAttribute('class','wt-cross-line');
    line.setAttribute('x1',sx);line.setAttribute('y1',sy);
    line.setAttribute('x2',dx);line.setAttribute('y2',dy);
    svg.appendChild(line);
  }});
}}

var WT_WINDOW_DAYS=30;

function wtCurrentWindow(){{return WT_WINDOW_DAYS;}}

function wtBubbleInWindow(b){{
  if(WT_WINDOW_DAYS>=99000) return true;
  return (b.age_days||0)<=WT_WINDOW_DAYS;
}}

function wtCellHasContent(cellKey){{
  // A cell stays visible if it has any finding inside the window OR any
  // unresolved finding regardless of age (long-runners shouldn't disappear
  // when zoomed in).
  var bubbles=(WT_DATA&&WT_DATA.bubbles)||[];
  var hasInWindow=false, hasUnresolved=false;
  for(var i=0;i<bubbles.length;i++){{
    var b=bubbles[i];
    if(b.cell!==cellKey) continue;
    if(wtBubbleInWindow(b)) hasInWindow=true;
    if(!b.is_resolved) hasUnresolved=true;
    if(hasInWindow&&hasUnresolved) break;
  }}
  return hasInWindow||hasUnresolved;
}}

function wtApplyCellCollapse(){{
  document.querySelectorAll('.wt-cell').forEach(function(g){{
    var key=g.getAttribute('data-cell');
    g.classList.toggle('wt-cell--collapsed', !wtCellHasContent(key));
  }});
}}

function wtSetWindow(days, persist){{
  WT_WINDOW_DAYS=days|0;
  document.querySelectorAll('.wt-slider-btn').forEach(function(b){{
    var on=parseInt(b.getAttribute('data-window'),10)===WT_WINDOW_DAYS;
    b.setAttribute('aria-pressed', on?'true':'false');
  }});
  if(persist!==false){{
    try{{localStorage.setItem('wt_window',String(WT_WINDOW_DAYS));}}catch(e){{}}
  }}
  wtRenderBubbles();
  wtApplyCellCollapse();
  // Trajectory watermark (Phase 6) listens for this same event
  window.dispatchEvent(new CustomEvent('wt:window-change',{{detail:{{days:WT_WINDOW_DAYS}}}}));
  trackUi('wt_window_changed',{{days:WT_WINDOW_DAYS}});
}}

function wtInitSlider(){{
  var saved=null;
  try{{saved=parseInt(localStorage.getItem('wt_window')||'',10);}}catch(e){{}}
  var initial=(saved&&[7,30,90,180,99999].indexOf(saved)>=0)?saved:30;
  document.querySelectorAll('.wt-slider-btn').forEach(function(b){{
    b.addEventListener('click',function(){{
      var d=parseInt(b.getAttribute('data-window'),10)||30;
      // Hide first-visit hint after any interaction
      try{{localStorage.setItem('wt_visited','1');}}catch(e){{}}
      var hint=document.getElementById('wt-slider-hint');
      if(hint) hint.classList.add('wt-hidden');
      wtSetWindow(d, true);
    }});
  }});
  wtSetWindow(initial, false);
  // First-visit hint: show for 8s then fade, hide for good after first click.
  var visited=null;
  try{{visited=localStorage.getItem('wt_visited');}}catch(e){{}}
  var hint=document.getElementById('wt-slider-hint');
  if(hint){{
    if(visited){{ hint.classList.add('wt-hidden'); }}
    else {{
      setTimeout(function(){{ hint.classList.add('wt-fading'); }},8000);
    }}
  }}
}}

// Update wtRenderBubbles to honor the time window — bubbles outside the window
// are skipped, except long-runners which pin to the cell's left edge with a
// "↤ Nd" chip so the user knows there's something below.
var _wtRenderBubblesOriginal=wtRenderBubbles;
wtRenderBubbles=function(){{
  var data=WT_DATA||{{}};
  var bubbles=data.bubbles||[];
  var pts=data.problem_types||[];
  var afs=data.affects||[];
  var byCell={{}};
  bubbles.forEach(function(b){{
    if(!byCell[b.cell]) byCell[b.cell]=[];
    byCell[b.cell].push(b);
  }});
  var maxAge=Math.max(7, WT_WINDOW_DAYS===99999?180:WT_WINDOW_DAYS);
  var g=wtCellGeometry();
  var padX=8, padY=8;
  var innerW=g.cellW-2*padX, innerH=g.cellH-2*padY;

  Object.keys(byCell).forEach(function(cellKey){{
    var layer=document.querySelector('.wt-bubble-layer[data-cell="'+cellKey+'"]');
    if(!layer) return;
    layer.innerHTML='';
    var list=byCell[cellKey].slice();
    list.sort(function(a,b){{return(a.risk_score||0)-(b.risk_score||0);}});

    // Pinned long-runners outside window: show one "↤ Nd" chip at left edge
    var pinned=list.filter(function(b){{return b.is_long_runner&&!wtBubbleInWindow(b);}});
    if(pinned.length){{
      var oldest=pinned.reduce(function(m,b){{return(b.shelf_days||0)>(m.shelf_days||0)?b:m;}},pinned[0]);
      var ns='http://www.w3.org/2000/svg';
      var pin=document.createElementNS(ns,'g');
      pin.setAttribute('class','wt-bubble--pinned');
      pin.setAttribute('transform','translate('+padX+','+(padY+4)+')');
      pin.style.cursor='pointer';
      var pinText=document.createElementNS(ns,'text');
      pinText.setAttribute('class','wt-cell-pin');
      pinText.setAttribute('font-family','system-ui,sans-serif');
      pinText.setAttribute('font-size','7');
      pinText.setAttribute('font-weight','700');
      pinText.setAttribute('fill','#94a3b8');
      pinText.textContent='↤'+oldest.shelf_days+'d';
      pin.appendChild(pinText);
      pin.addEventListener('click',function(e){{
        e.stopPropagation();
        wtSelectFinding(oldest.id);
      }});
      pin.addEventListener('mouseenter',function(){{wtShowTooltip(oldest,pin);}});
      pin.addEventListener('mouseleave',wtHideTooltip);
      pin.addEventListener('mousemove',function(e){{wtMoveTooltip(e);}});
      layer.appendChild(pin);
    }}

    list.forEach(function(b,idx){{
      if(!wtBubbleInWindow(b)) return; // non-pinned bubbles drop when outside window
      var ageRatio=Math.max(0,Math.min(1,1-((b.age_days||0)/maxAge)));
      var riskRatio=Math.max(0,Math.min(1,(b.risk_score||0)/100));
      var bx=padX + ageRatio*innerW;
      var by=padY + (1-riskRatio)*innerH;
      var seed=0;
      for(var i=0;i<(b.id||'').length;i++) seed=(seed*31+(b.id.charCodeAt(i)))&0xffff;
      var jx=((seed%7)-3)*0.6, jy=(((seed>>3)%7)-3)*0.6;
      bx=Math.max(padX-2,Math.min(g.cellW-padX+2,bx+jx));
      by=Math.max(padY-2,Math.min(g.cellH-padY+2,by+jy));
      var r=wtBubbleRadius(b.risk_score);
      var classes=['wt-bubble'];
      if(b.is_kev||(b.epss!==null&&b.epss!==undefined&&b.epss>=0.7)) classes.push('wt-bubble--urgent');
      if(b.is_low_confidence) classes.push('wt-bubble--low-conf');
      if(b.is_long_runner) classes.push('wt-bubble--long-runner');
      if(b.is_resolved) classes.push('wt-bubble--resolved');
      if(b.recategorized_within_24h) classes.push('wt-bubble--moved');
      // Greyscale-first palette: bubble body is always neutral grey.  Priority
      // is encoded by *outline* — red for P1/critical, yellow for P2/elevated,
      // a dimmer grey for P3.  KEV upgrades the outline to a brighter red.
      var color = b.is_resolved ? '#5a626d'
                : b.priority==='P1' ? '#cbd3dd'
                : b.priority==='P2' ? '#a5afbe'
                : '#7a8493';
      var stroke = b.is_kev          ? '#f87171'
                 : b.priority==='P1' ? '#ef4444'
                 : b.priority==='P2' ? '#eab308'
                 : '#6b7382';
      var ns='http://www.w3.org/2000/svg';
      var grp=document.createElementNS(ns,'g');
      grp.setAttribute('class',classes.join(' '));
      grp.setAttribute('data-finding-id',b.id);
      grp.setAttribute('transform','translate('+bx.toFixed(2)+','+by.toFixed(2)+')');
      grp.setAttribute('role','button');
      grp.setAttribute('tabindex','0');
      var ariaParts=[(b.title||''),(b.priority||''),'risk '+(b.risk_score||0)];
      if(b.is_kev) ariaParts.push('KEV-listed');
      if(b.is_long_runner) ariaParts.push(b.shelf_days+' days unresolved');
      if(b.is_resolved) ariaParts.push('resolved');
      grp.setAttribute('aria-label', ariaParts.filter(Boolean).join(', '));
      grp.style.cursor='pointer';
      // Soft urgency halo: thin red blurred ring (no body fill) — keeps the
      // critical signal but stays minimal in greyscale context.
      if(classes.indexOf('wt-bubble--urgent')>=0){{
        var halo=document.createElementNS(ns,'circle');
        halo.setAttribute('class','wt-bubble-halo');
        halo.setAttribute('r',(r+4.5).toFixed(2));
        halo.setAttribute('fill','none');
        halo.setAttribute('stroke','#f87171');
        halo.setAttribute('stroke-width','1.6');
        halo.setAttribute('opacity','0.55');
        halo.setAttribute('filter','url(#wt-bubble-halo)');
        grp.appendChild(halo);
      }}
      // Long-runner outer ring + Nd label — softened
      if(classes.indexOf('wt-bubble--long-runner')>=0){{
        var ring=document.createElementNS(ns,'circle');
        ring.setAttribute('class','wt-bubble-ring');
        ring.setAttribute('r',(r+2.4).toFixed(2));
        ring.setAttribute('fill','none');
        ring.setAttribute('stroke','#a5afbe');
        ring.setAttribute('stroke-width','0.9');
        ring.setAttribute('opacity','0.55');
        grp.appendChild(ring);
        if((b.shelf_days||0)>=1){{
          var lbl=document.createElementNS(ns,'text');
          lbl.setAttribute('class','wt-bubble-runner-label');
          lbl.setAttribute('x','0');
          lbl.setAttribute('y',(r+9).toFixed(2));
          lbl.setAttribute('text-anchor','middle');
          lbl.setAttribute('font-family','system-ui,-apple-system,sans-serif');
          lbl.setAttribute('font-size','6.5');
          lbl.setAttribute('font-weight','600');
          lbl.setAttribute('fill','#7a8493');
          lbl.setAttribute('opacity','0.75');
          lbl.textContent=b.shelf_days+'d';
          grp.appendChild(lbl);
        }}
      }}
      var lockRing=document.createElementNS(ns,'circle');
      lockRing.setAttribute('class','wt-bubble-lock-ring');
      lockRing.setAttribute('r',(r+3.4).toFixed(2));
      lockRing.setAttribute('fill','none');
      lockRing.setAttribute('stroke','#cbd3dd');
      lockRing.setAttribute('stroke-width','0');
      lockRing.setAttribute('opacity','0');
      grp.appendChild(lockRing);
      // Body: greyscale disc with a subtle drop shadow.  Outline carries the
      // priority signal — heavier when the finding is P1 or KEV-listed.
      var isCrit = b.is_kev || b.priority==='P1';
      var isElev = b.priority==='P2';
      var strokeWidth = b.is_low_confidence ? '1.0'
                      : isCrit ? '1.6'
                      : isElev ? '1.2'
                      : '0.5';
      var body=document.createElementNS(ns,'circle');
      body.setAttribute('class','wt-bubble-body');
      body.setAttribute('r',r.toFixed(2));
      body.setAttribute('fill',color);
      body.setAttribute('fill-opacity', b.is_resolved?'0.32':'0.72');
      body.setAttribute('stroke',stroke);
      body.setAttribute('stroke-opacity', b.is_resolved?'0.45':isCrit?'1':'0.85');
      body.setAttribute('stroke-width', strokeWidth);
      body.setAttribute('filter','url(#wt-bubble-shadow)');
      grp.appendChild(body);
      // Subtle inner highlight only on bigger bubbles for depth without gloss.
      if(r>=4){{
        var hi=document.createElementNS(ns,'circle');
        hi.setAttribute('r',r.toFixed(2));
        hi.setAttribute('fill','url(#wt-bubble-grad)');
        hi.setAttribute('pointer-events','none');
        hi.setAttribute('opacity', b.is_resolved?'0.18':'0.35');
        grp.appendChild(hi);
      }}
      if(classes.indexOf('wt-bubble--moved')>=0){{
        var badge=document.createElementNS(ns,'text');
        badge.setAttribute('class','wt-bubble-moved-badge');
        badge.setAttribute('x',(r+1.5).toFixed(2));
        badge.setAttribute('y',(-r).toFixed(2));
        badge.setAttribute('font-size','7');
        badge.setAttribute('fill','#79b8ff');
        badge.setAttribute('font-family','system-ui,sans-serif');
        badge.setAttribute('opacity','0');
        badge.textContent='↻';
        grp.appendChild(badge);
      }}
      grp.addEventListener('mouseenter',function(){{
        wtShowTooltip(b,grp);
        var card=WT_CARDS_BY_ID[b.id];
        if(card&&Array.isArray(card.cross_cutting)&&card.cross_cutting.length){{
          wtClearCrossCuttingLines();
          wtDrawCrossCuttingLines(card,b.id);
        }}
      }});
      grp.addEventListener('mouseleave',function(){{
        wtHideTooltip();
        if(!WT_LOCKED_FINDING) wtClearCrossCuttingLines();
        else if(WT_LOCKED_FINDING!==b.id){{
          var lc=WT_CARDS_BY_ID[WT_LOCKED_FINDING];
          if(lc&&Array.isArray(lc.cross_cutting)){{
            wtClearCrossCuttingLines();
            wtDrawCrossCuttingLines(lc,WT_LOCKED_FINDING);
          }}
        }}
      }});
      grp.addEventListener('mousemove',function(e){{wtMoveTooltip(e);}});
      grp.addEventListener('click',function(e){{
        e.stopPropagation();
        wtSelectFinding(b.id);
      }});
      layer.appendChild(grp);
    }});
  }});
}};

function wtRenderTrajectory(){{
  // Subtle horizon-style stacked area along the BOTTOM of the matrix.
  // Capped at ~22% of grid height with a 5-day moving average so single
  // spikes don't produce harsh wedges.  Each band tops with a fade-out.
  var data=WT_DATA||{{}};
  var traj=data.trajectory||{{}};
  var afs=data.affects||[];
  var afColors=data.affects_colors||{{}};
  var anchor=document.getElementById('wt-trajectory');
  if(!anchor) return;
  while(anchor.firstChild) anchor.removeChild(anchor.firstChild);
  if(!afs.length||!Object.keys(traj).length) return;

  var g=wtCellGeometry();
  var window_=Math.max(7, WT_WINDOW_DAYS===99999?180:WT_WINDOW_DAYS);
  var x0=g.labelLeft, x1=g.labelLeft+g.cellW*10+g.gutterX*9;
  var y0=g.labelTop, y1=g.labelTop+g.cellH*8+g.gutterY*7;
  var width=x1-x0, height=y1-y0;
  // Watermark height capped at 22% of grid; anchored at the bottom.
  var bandH=Math.max(28, Math.min(110, height*0.22));
  var baseY=y1; // bottom of grid
  var topY=y1-bandH;

  var bandSeries=afs.map(function(af){{
    var s=traj[af]||[];
    return {{af:af,points:s.slice(-window_)}};
  }});
  var nDays=bandSeries[0].points.length||1;

  // 5-day moving average smooths jagged spikes into gentle curves.
  function smooth(series){{
    var smoothed=new Array(series.length).fill(0);
    var half=2; // ±2 days = 5-day window
    for(var i=0;i<series.length;i++){{
      var sum=0,cnt=0;
      for(var j=Math.max(0,i-half);j<=Math.min(series.length-1,i+half);j++){{ sum+=series[j]; cnt++; }}
      smoothed[i]=cnt?sum/cnt:0;
    }}
    return smoothed;
  }}
  bandSeries.forEach(function(band){{
    band.smoothed=smooth(band.points.map(function(p){{return p.n||0;}}));
  }});

  var dayTotals=new Array(nDays).fill(0);
  bandSeries.forEach(function(b){{
    b.smoothed.forEach(function(v,i){{ dayTotals[i]+=v; }});
  }});
  var maxTotal=Math.max(1, dayTotals.reduce(function(m,v){{return Math.max(m,v);}},0));

  // Build stacked paths using cubic-bezier between sample points for
  // smoothness.  Each band gets a fade-out gradient at its top.
  function buildSmoothPath(topPts,bottomPts){{
    if(topPts.length<2) return '';
    var d='M '+topPts[0][0]+' '+topPts[0][1];
    for(var i=1;i<topPts.length;i++){{
      var p0=topPts[i-1], p1=topPts[i];
      var cx=(p0[0]+p1[0])/2;
      d+=' C '+cx+' '+p0[1]+', '+cx+' '+p1[1]+', '+p1[0]+' '+p1[1];
    }}
    for(var j=bottomPts.length-1;j>=0;j--){{
      d+=' L '+bottomPts[j][0]+' '+bottomPts[j][1];
    }}
    d+=' Z';
    return d;
  }}

  var ns='http://www.w3.org/2000/svg';
  var stackBelow=new Array(nDays).fill(0);
  bandSeries.forEach(function(band){{
    // Greyscale-only watermark; per-row color comes from the AFFECTS_COLORS
    // grey palette we already greyscaled.  Each band reads as a soft layer
    // of the same dim grey, with deeper layers slightly darker.
    var color=afColors[band.af]||'#7a8493';
    var topPts=[], bottomPts=[];
    band.smoothed.forEach(function(v,i){{
      var px=x0 + (i/(nDays-1||1))*width;
      var below=stackBelow[i];
      var top=below+v;
      var pyTop=baseY - (top/maxTotal)*bandH;
      var pyBot=baseY - (below/maxTotal)*bandH;
      topPts.push([+px.toFixed(2), +pyTop.toFixed(2)]);
      bottomPts.push([+px.toFixed(2), +pyBot.toFixed(2)]);
      stackBelow[i]=top;
    }});
    var pathD=buildSmoothPath(topPts,bottomPts);
    if(!pathD) return;
    var p=document.createElementNS(ns,'path');
    p.setAttribute('d',pathD);
    p.setAttribute('fill',color);
    p.setAttribute('fill-opacity','0.085');
    p.setAttribute('stroke',color);
    p.setAttribute('stroke-opacity','0.18');
    p.setAttribute('stroke-width','0.5');
    p.setAttribute('data-affects',band.af);
    p.setAttribute('pointer-events','none');
    anchor.appendChild(p);
  }});

  // Soft horizon line so the watermark has a clean baseline edge.
  var horizon=document.createElementNS(ns,'line');
  horizon.setAttribute('x1',x0);
  horizon.setAttribute('y1',baseY);
  horizon.setAttribute('x2',x1);
  horizon.setAttribute('y2',baseY);
  horizon.setAttribute('stroke','#1f2530');
  horizon.setAttribute('stroke-opacity','0.5');
  horizon.setAttribute('stroke-width','0.6');
  horizon.setAttribute('pointer-events','none');
  anchor.appendChild(horizon);

  // Hover-capture is constrained to the watermark band only (not the entire
  // grid as before — which interfered with bubble interaction).
  var hover=document.createElementNS(ns,'rect');
  hover.setAttribute('x',x0);
  hover.setAttribute('y',topY);
  hover.setAttribute('width',width);
  hover.setAttribute('height',bandH);
  hover.setAttribute('fill','transparent');
  hover.setAttribute('pointer-events','all');
  hover.style.cursor='crosshair';
  hover.addEventListener('mousemove',function(e){{
    var svg=document.getElementById('wt-matrix-svg');
    if(!svg) return;
    var pt=svg.createSVGPoint();
    pt.x=e.clientX; pt.y=e.clientY;
    var ctm=svg.getScreenCTM();
    if(!ctm) return;
    var local=pt.matrixTransform(ctm.inverse());
    var fx=Math.max(0,Math.min(1,(local.x-x0)/width));
    var idx=Math.min(nDays-1, Math.max(0, Math.floor(fx*(nDays-1))));
    var lines=bandSeries.map(function(band){{
      var n=band.points[idx]?.n||0;
      var col=afColors[band.af]||'#94a3b8';
      return '<div style="display:flex;justify-content:space-between;gap:.6rem"><span style="color:'+col+'">'
        +(data.affects_labels[band.af]||band.af)+'</span><span>'+n+'</span></div>';
    }}).join('');
    var d=bandSeries[0].points[idx]?.d||'';
    var el=wtEnsureTooltip();
    el.innerHTML='<strong>'+d+'</strong>'+lines;
    el.style.opacity='1';
    wtMoveTooltip(e);
  }});
  hover.addEventListener('mouseleave',wtHideTooltip);
  anchor.appendChild(hover);
  anchor.setAttribute('opacity','1');
}}

window.addEventListener('wt:window-change',function(){{ wtRenderTrajectory(); }});

function wtInitMatrix(){{
  if(!WT_DATA||!WT_DATA.cells) return;
  document.querySelectorAll('.wt-cell').forEach(function(g){{
    var key=g.getAttribute('data-cell');
    g.addEventListener('click',function(e){{
      e.stopPropagation();
      if(WT_CURRENT_CELL===key&&!WT_LOCKED_FINDING){{
        wtSelectCell('all');
      }} else {{
        wtSelectCell(key);
      }}
    }});
  }});
  document.querySelectorAll('.wt-row-label').forEach(function(g){{
    g.addEventListener('click',function(){{
      var af=g.getAttribute('data-affects');
      var data=WT_DATA||{{}};
      var best=null,bestRisk=-1;
      (data.problem_types||[]).forEach(function(pt){{
        var ck=pt+'|'+af;
        var c=(data.cells||{{}})[ck];
        if(c&&c.max_risk>bestRisk){{bestRisk=c.max_risk;best=ck;}}
      }});
      if(best) wtSelectCell(best);
    }});
  }});
  var svg=document.getElementById('wt-matrix-svg');
  if(svg){{
    svg.addEventListener('click',function(e){{
      if(e.target===svg) wtSelectCell('all');
    }});
  }}
  wtInitSlider(); // also calls wtRenderBubbles + wtApplyCellCollapse
  wtRenderTrajectory();
  wtInitKeyboardNav();
}}

function wtInitKeyboardNav(){{
  // Escape unlocks; arrow keys move between cells; Enter activates focused cell.
  document.addEventListener('keydown',function(e){{
    if(e.key==='Escape'){{
      if(WT_LOCKED_FINDING||WT_CURRENT_CELL!=='all'){{
        wtSelectCell('all');
        e.preventDefault();
      }}
      return;
    }}
    var active=document.activeElement;
    if(!active) return;
    if(active.classList&&active.classList.contains('wt-cell')){{
      var key=active.getAttribute('data-cell');
      if(!key) return;
      var parts=key.split('|');
      var pt=parts[0], af=parts[1];
      var data=WT_DATA||{{}};
      var pts=data.problem_types||[];
      var afs=data.affects||[];
      var ci=pts.indexOf(pt), ri=afs.indexOf(af);
      var nci=ci, nri=ri;
      if(e.key==='ArrowRight') nci=Math.min(pts.length-1, ci+1);
      else if(e.key==='ArrowLeft') nci=Math.max(0, ci-1);
      else if(e.key==='ArrowDown') nri=Math.min(afs.length-1, ri+1);
      else if(e.key==='ArrowUp') nri=Math.max(0, ri-1);
      else if(e.key==='Enter'||e.key===' '){{
        wtSelectCell(key);
        e.preventDefault();
        return;
      }} else return;
      if(nci===ci&&nri===ri) return;
      var nextKey=pts[nci]+'|'+afs[nri];
      var nextEl=document.querySelector('.wt-cell[data-cell="'+nextKey+'"]');
      if(nextEl){{
        nextEl.focus();
        e.preventDefault();
      }}
    }} else if(active.classList&&active.classList.contains('wt-bubble')){{
      if(e.key==='Enter'||e.key===' '){{
        var fid=active.getAttribute('data-finding-id');
        if(fid){{ wtSelectFinding(fid); e.preventDefault(); }}
      }}
    }}
  }});
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
function remCycle(btn){{
  var card=btn.closest('.cluster');
  if(!card)return;
  var id=card.id.replace(/^card-/,'');
  var states=['unack','inprog','accepted','mitigated'];
  var cur=card.getAttribute('data-rem-state')||'unack';
  var next=states[(states.indexOf(cur)+1)%states.length];
  try{{
    var r=JSON.parse(localStorage.getItem('wt.remediation')||'{{}}');
    if(next==='unack')delete r[id];else r[id]=next;
    localStorage.setItem('wt.remediation',JSON.stringify(r));
  }}catch(e){{}}
  _remApply(card,next,btn);
  _remUpdateAlerts(id,next);
}}
function _remApply(card,state,btn){{
  card.setAttribute('data-rem-state',state);
  var icons={{unack:'\u2299',inprog:'\u27f3',accepted:'\u2713',mitigated:'\u2298'}};
  var titles={{unack:'Remediation: Unacknowledged',inprog:'Remediation: In Progress',accepted:'Remediation: Accepted Risk',mitigated:'Remediation: Mitigated'}};
  if(btn){{btn.textContent=icons[state]||'\u2299';btn.title=titles[state]||state;}}
}}
function _remUpdateAlerts(id,state){{
  document.querySelectorAll('.alert-row[data-card-id="'+id+'"]').forEach(function(row){{
    row.style.display=state==='mitigated'?'none':'';
  }});
}}
function initRemediationTracker(){{
  var r={{}};
  try{{r=JSON.parse(localStorage.getItem('wt.remediation')||'{{}}');}}catch(e){{}}
  Object.keys(r).forEach(function(id){{
    var card=document.getElementById('card-'+id);
    if(!card)return;
    var btn=card.querySelector('.rem-pill');
    _remApply(card,r[id],btn);
    _remUpdateAlerts(id,r[id]);
  }});
}}
initRemediationTracker();
initRightRail();
selectDomain('all');
wtInitMatrix();
initFindingsFilter();
</script>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(page_html)
