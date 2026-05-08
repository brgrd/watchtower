"""Trajectory aggregation for the matrix watermark.

Builds a per-day, per-affects-layer count series so the matrix can render a
faint stacked-area watermark behind itself.  The watermark answers the gestalt
question "is this layer trending hot?" without competing visually with cells.

Daily counts are derived from the briefing JSONL archive plus the current
``finding_shelf`` so the series is stable across page renders even when the
current run produced few cards.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from agent.matrix import AFFECTS_ORDER


def _parse_briefing_filename(fname: str) -> datetime | None:
    if not (fname.startswith("briefing_") and fname.endswith(".jsonl")):
        return None
    stem = fname[len("briefing_") : -len(".jsonl")]
    try:
        return datetime.strptime(stem, "%Y-%m-%d_%H-%M").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def build_trajectory(
    cards: list,
    reports_dir: str,
    finding_shelf: dict | None = None,
    *,
    window_days: int = 180,
    now: datetime | None = None,
) -> dict:
    """Return ``{affects_layer: [{d: 'YYYY-MM-DD', n: int}, ...]}``.

    Each layer carries one entry per day in the ``window_days`` window ending
    today.  Counts come from the most recent briefing of each calendar day in
    the archive; days without a briefing produce a zero entry so the resulting
    timeseries is dense and easy to render as an SVG path.
    """
    now = now or datetime.now(timezone.utc)
    finding_shelf = finding_shelf or {}

    # --- Day index from briefing JSONL archive ---------------------------------
    daily_cards: dict = {}
    if os.path.isdir(reports_dir):
        # For each calendar date, keep the latest run's cards
        latest_per_date: dict = {}
        for fname in sorted(os.listdir(reports_dir)):
            dt = _parse_briefing_filename(fname)
            if dt is None:
                continue
            date_key = dt.strftime("%Y-%m-%d")
            existing = latest_per_date.get(date_key)
            if existing is None or dt > existing[0]:
                latest_per_date[date_key] = (dt, os.path.join(reports_dir, fname))
        for date_key, (_dt, fp) in latest_per_date.items():
            day_cards = []
            try:
                with open(fp, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            day_cards.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue
            daily_cards[date_key] = day_cards

    # Today's cards take precedence — current run may be more recent than
    # any committed JSONL.
    today_key = now.strftime("%Y-%m-%d")
    if cards:
        daily_cards[today_key] = cards

    # --- Build per-layer counts per day ---------------------------------------
    series: dict = {a: [] for a in AFFECTS_ORDER}
    start = (now - timedelta(days=window_days - 1)).date()
    for offset in range(window_days):
        d = (start + timedelta(days=offset)).strftime("%Y-%m-%d")
        per_layer = {a: 0 for a in AFFECTS_ORDER}
        for card in daily_cards.get(d, []):
            af = card.get("affects") or (
                finding_shelf.get(card.get("id", ""), {}).get("last_affects")
            )
            if af and af in per_layer:
                per_layer[af] += 1
        for a in AFFECTS_ORDER:
            series[a].append({"d": d, "n": per_layer[a]})

    return series
