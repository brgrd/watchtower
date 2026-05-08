"""Threat-matrix layout and data preparation.

The matrix replaces the legacy domain constellation with a stable grid where:
    columns = problem_type   (rce, auth_bypass, ...)
    rows    = affects        (foundation, application, ...)

Each cell is a micro-canvas hosting individual finding bubbles whose position
encodes (time, criticality) within the cell.  This module prepares the JSON
data structure consumed by html_builder; SVG rendering and reactive behavior
live alongside in html_builder.py and the embedded petite-vue script.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Iterable

from agent.analysis import AFFECTS, PROBLEM_TYPES

# Fixed display order — also defines column / row indices.  Order chosen so
# the most-actionable problems sit on the left and the deepest layers sit at
# the bottom (foundation issues feel "underneath" everything else).
PROBLEM_TYPE_ORDER: list = [
    "rce",
    "privilege_escalation",
    "auth_bypass",
    "data_disclosure",
    "data_tampering",
    "credential_compromise",
    "supply_chain",
    "crypto_weakness",
    "dos",
    "misconfiguration",
]
AFFECTS_ORDER: list = [
    "user_data",
    "application",
    "framework",
    "runtime",
    "service",
    "network",
    "build_pipeline",
    "foundation",
]

# Pretty labels for axis headers.
PROBLEM_TYPE_LABELS: dict = {
    "rce": "RCE",
    "privilege_escalation": "Priv Esc",
    "auth_bypass": "Auth Bypass",
    "data_disclosure": "Data Leak",
    "data_tampering": "Tampering",
    "credential_compromise": "Cred Compromise",
    "supply_chain": "Supply Chain",
    "crypto_weakness": "Crypto",
    "dos": "DoS",
    "misconfiguration": "Misconfig",
}
AFFECTS_LABELS: dict = {
    "user_data": "User Data",
    "application": "Application",
    "framework": "Framework",
    "runtime": "Runtime",
    "service": "Service",
    "network": "Network",
    "build_pipeline": "Build Pipeline",
    "foundation": "Foundation",
}

# Per-row palette for the matrix.  The matrix is intentionally greyscale —
# colour is reserved for criticality cues (red/yellow accents elsewhere).
# Each row gets a slightly different neutral grey so the eye can still
# distinguish stack layers without competing with the priority signal.
# Lighter = closer to user; darker = deeper in the stack.
AFFECTS_COLORS: dict = {
    "user_data":      "#b8c0cc",  # lightest — surface / end-user data
    "application":    "#a8b0bc",
    "framework":      "#98a0ac",
    "runtime":        "#88909c",
    "service":        "#78808c",
    "network":        "#68707c",
    "build_pipeline": "#58606c",
    "foundation":     "#48505c",  # darkest — kernel / libc, the calm depths
}


def _coerce_iso_date(s: str) -> datetime | None:
    if not s:
        return None
    try:
        # Accepts both 'YYYY-MM-DD' and full ISO timestamps
        if len(s) == 10:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _age_days(ts: str, now: datetime) -> float:
    dt = _coerce_iso_date(ts)
    if dt is None:
        return 0.0
    return max(0.0, (now - dt).total_seconds() / 86400.0)


def _cell_key(problem_type: str, affects: str) -> str:
    return f"{problem_type}|{affects}"


def build_matrix_data(cards: list, *, now: datetime | None = None) -> dict:
    """Return the JSON payload that drives the matrix view.

    Output shape::

        {
            "problem_types": [...],          # column keys, ordered
            "affects":       [...],          # row keys, ordered
            "problem_type_labels": {...},
            "affects_labels":     {...},
            "affects_colors":     {...},
            "cells":  { "rce|framework": {
                "findings":         [card_id, ...],     # ordered by risk_score desc
                "active_count":     int,
                "long_runner_count":int,
                "p1_count":         int,
                "max_risk":         int,
                "any_kev":          bool,
                "any_low_confidence": bool,
            }, ... },
            "bubbles": [ {                              # one entry per visible bubble
                "id":           card_id,
                "cell":         "rce|framework",
                "title":        str,
                "risk_score":   int,
                "priority":     "P1"|"P2"|"P3"|"",
                "age_days":     float,
                "shelf_days":   int,
                "first_seen":   "YYYY-MM-DD",
                "is_kev":       bool,
                "is_long_runner": bool,
                "is_low_confidence": bool,
                "is_resolved":  bool,
                "epss":         float|None,
                "classification_reasoning": str,
                "cross_cutting": [cell_key, ...],
            }, ... ],
            "row_totals":    { affects: int, ... },
            "column_totals": { problem_type: int, ... },
            "now_iso":       str,
        }
    """
    now = now or datetime.now(timezone.utc)
    valid_problem = set(PROBLEM_TYPES)
    valid_affects = set(AFFECTS)

    cells: dict = {}
    bubbles: list = []
    row_totals: dict = {a: 0 for a in AFFECTS_ORDER}
    column_totals: dict = {p: 0 for p in PROBLEM_TYPE_ORDER}

    for card in cards:
        if not isinstance(card, dict):
            continue
        pt = card.get("problem_type", "")
        af = card.get("affects", "")
        if pt not in valid_problem or af not in valid_affects:
            # Phase 1 ensures these are populated; this is just defense in depth
            continue

        cell_key = _cell_key(pt, af)
        cell = cells.setdefault(
            cell_key,
            {
                "findings": [],
                "active_count": 0,
                "long_runner_count": 0,
                "p1_count": 0,
                "max_risk": 0,
                "any_kev": False,
                "any_low_confidence": False,
            },
        )

        risk = int(card.get("risk_score", 0))
        priority = str(card.get("priority", "")).upper()
        shelf_days = int(card.get("shelf_days", 0))
        is_resolved = bool(card.get("shelf_resolved"))
        is_kev = bool(card.get("is_kev"))
        cls_conf = float(card.get("classification_confidence", 1.0) or 1.0)
        is_long_runner = (not is_resolved) and shelf_days > 7
        is_low_confidence = cls_conf < 0.7

        cell["findings"].append(card.get("id", ""))
        cell["active_count"] += 0 if is_resolved else 1
        cell["long_runner_count"] += 1 if is_long_runner else 0
        cell["p1_count"] += 1 if priority == "P1" else 0
        cell["max_risk"] = max(cell["max_risk"], risk)
        cell["any_kev"] = cell["any_kev"] or is_kev
        cell["any_low_confidence"] = cell["any_low_confidence"] or is_low_confidence

        row_totals[af] = row_totals.get(af, 0) + 1
        column_totals[pt] = column_totals.get(pt, 0) + 1

        first_seen = card.get("first_seen_ts") or ""
        age = _age_days(first_seen, now) if first_seen else 0.0

        epss = card.get("epss_score")
        try:
            epss = float(epss) if epss is not None else None
        except (TypeError, ValueError):
            epss = None

        cross_cutting = list(card.get("cross_cutting") or [])

        bubbles.append(
            {
                "id": card.get("id", ""),
                "cell": cell_key,
                "title": card.get("title", ""),
                "risk_score": risk,
                "priority": priority,
                "age_days": round(age, 2),
                "shelf_days": shelf_days,
                "first_seen": first_seen,
                "is_kev": is_kev,
                "is_long_runner": is_long_runner,
                "is_low_confidence": is_low_confidence,
                "is_resolved": is_resolved,
                "epss": epss,
                "classification_reasoning": card.get("classification_reasoning", "") or "",
                "cross_cutting": cross_cutting,
                "recategorized_within_24h": bool(card.get("recategorized_within_24h")),
            }
        )

    # Sort findings within each cell by risk_score desc for deterministic display
    risk_lookup = {c.get("id", ""): int(c.get("risk_score", 0)) for c in cards if isinstance(c, dict)}
    for cell in cells.values():
        cell["findings"].sort(key=lambda fid: -risk_lookup.get(fid, 0))

    return {
        "problem_types": list(PROBLEM_TYPE_ORDER),
        "affects": list(AFFECTS_ORDER),
        "problem_type_labels": dict(PROBLEM_TYPE_LABELS),
        "affects_labels": dict(AFFECTS_LABELS),
        "affects_colors": dict(AFFECTS_COLORS),
        "cells": cells,
        "bubbles": bubbles,
        "row_totals": row_totals,
        "column_totals": column_totals,
        "now_iso": now.isoformat(),
    }


def _threat_level(district: dict) -> str:
    """Map an aggregated district to one of four threat tiers.

    The tiers drive both the visual treatment (border colour, label chip) and
    the immediate-glance read of a zone.  Anchor on the loudest signal:
    KEV-listed and P1 findings always promote a zone to critical regardless
    of count, since one critical issue is enough to demand attention.
    """
    if district.get("active_count", 0) == 0:
        return "quiet"
    if district.get("any_kev") or district.get("p1_count", 0) > 0 or district.get("max_risk", 0) >= 85:
        return "critical"
    if district.get("max_risk", 0) >= 65:
        return "elevated"
    return "watch"


def build_districts_data(cards: list, *, now: datetime | None = None) -> dict:
    """Aggregate cards by ``affects`` layer for the threat-districts view.

    The districts view replaces the cell-grid-of-bubbles concept with one
    large named zone per affects layer, each carrying its threat level,
    aggregate counts, and the actual finding titles inline (visible without
    clicking).  Cross-tabulation with ``problem_type`` is exposed via filter
    chips above the districts rather than as a second axis.

    Output shape::

        {
            "districts": {
                "user_data": {
                    "affects": "user_data",
                    "label": "User Data",
                    "threat_level": "critical"|"elevated"|"watch"|"quiet",
                    "active_count": int,
                    "p1_count": int,
                    "max_risk": int,
                    "any_kev": bool,
                    "long_runner_count": int,
                    "problem_types": {pt: count, ...},
                    "findings": [card_id, ...],   # active first, sorted by risk
                },
                ...
            },
            "order": [...],                       # top-of-stack to deepest
            "labels": {...},
            "problem_type_counts": {pt: count, ...},
            "now_iso": str,
        }
    """
    now = now or datetime.now(timezone.utc)
    valid_affects = set(AFFECTS)

    districts: dict = {
        a: {
            "affects": a,
            "label": AFFECTS_LABELS.get(a, a),
            "threat_level": "quiet",
            "active_count": 0,
            "p1_count": 0,
            "max_risk": 0,
            "any_kev": False,
            "long_runner_count": 0,
            "problem_types": {},
            "findings": [],
        }
        for a in AFFECTS_ORDER
    }

    problem_type_counts: dict = {}

    for card in cards:
        if not isinstance(card, dict):
            continue
        af = card.get("affects", "")
        if af not in valid_affects:
            continue
        d = districts[af]
        is_resolved = bool(card.get("shelf_resolved"))
        risk = int(card.get("risk_score", 0))
        priority = str(card.get("priority", "")).upper()
        shelf_days = int(card.get("shelf_days", 0))
        is_kev = bool(card.get("is_kev"))
        pt = card.get("problem_type", "")

        if not is_resolved:
            d["active_count"] += 1
        if priority == "P1":
            d["p1_count"] += 1
        if risk > d["max_risk"]:
            d["max_risk"] = risk
        if is_kev:
            d["any_kev"] = True
        if (not is_resolved) and shelf_days > 7:
            d["long_runner_count"] += 1
        if pt:
            d["problem_types"][pt] = d["problem_types"].get(pt, 0) + 1
            problem_type_counts[pt] = problem_type_counts.get(pt, 0) + 1
        d["findings"].append(card.get("id", ""))

    risk_lookup = {
        c.get("id", ""): int(c.get("risk_score", 0))
        for c in cards
        if isinstance(c, dict)
    }
    for d in districts.values():
        d["findings"].sort(key=lambda fid: -risk_lookup.get(fid, 0))
        d["threat_level"] = _threat_level(d)

    return {
        "districts": districts,
        "order": list(AFFECTS_ORDER),
        "labels": dict(AFFECTS_LABELS),
        "problem_type_labels": dict(PROBLEM_TYPE_LABELS),
        "problem_type_counts": problem_type_counts,
        "now_iso": now.isoformat(),
    }


def cell_geometry(cols: int = 10, rows: int = 8) -> dict:
    """Return SVG layout constants for the matrix grid.

    Kept here so html_builder and tests can share a single source of truth for
    cell dimensions, gutters, and label widths.
    """
    cell_w = 88
    cell_h = 64
    gutter_x = 6
    gutter_y = 6
    label_left = 110     # row label gutter
    label_top = 28       # column label gutter
    margin = 8

    grid_w = cols * cell_w + (cols - 1) * gutter_x
    grid_h = rows * cell_h + (rows - 1) * gutter_y
    return {
        "cell_w": cell_w,
        "cell_h": cell_h,
        "gutter_x": gutter_x,
        "gutter_y": gutter_y,
        "label_left": label_left,
        "label_top": label_top,
        "margin": margin,
        "view_w": label_left + grid_w + margin,
        "view_h": label_top + grid_h + margin + 16,  # +16 for axis ticks
        "grid_w": grid_w,
        "grid_h": grid_h,
    }


def cell_origin(col_index: int, row_index: int, geom: dict | None = None) -> tuple:
    """Top-left corner (x, y) of cell (col_index, row_index) in SVG coordinates."""
    g = geom or cell_geometry()
    x = g["label_left"] + col_index * (g["cell_w"] + g["gutter_x"])
    y = g["label_top"] + row_index * (g["cell_h"] + g["gutter_y"])
    return x, y


def bubble_radius(risk_score: int) -> float:
    """Map a 0..100 risk_score to a bubble radius in px.

    Logarithmic so high scores don't dominate the cell.  Clamped 2.0..9.0.
    """
    score = max(1, int(risk_score))
    r = 1.4 * math.log(score + 1) + 1.6
    return max(2.0, min(9.0, r))
