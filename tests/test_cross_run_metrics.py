"""Tests for cross-run weekly metrics and history lifecycle annotation.

Covers:
  - runner._compute_weekly_cross_run()
  - runner._annotate_history_lifecycle()
  - html_builder._build_velocity_sparkline()
  - html_builder._build_weekly_section() cross-run tile rendering
  - html_builder._build_history_accordion() lifecycle badge rendering
"""

import pytest

from agent.runner import _compute_weekly_cross_run, _annotate_history_lifecycle
from agent.html_builder import (
    _build_velocity_sparkline,
    _build_weekly_section,
    _build_history_accordion,
)

pytestmark = pytest.mark.unit


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _card(cve="CVE-2026-1111", risk=70, priority="P1", patch="no_fix",
          shelf_resolved=False, run_count=1):
    return {
        "id": f"card-{cve}",
        "title": f"Vuln in openssl ({cve})",
        "summary": f"Critical issue tracked as {cve}.",
        "risk_score": risk,
        "priority": priority,
        "patch_status": patch,
        "shelf_resolved": shelf_resolved,
        "run_count": run_count,
        "shelf_days": 1,
        "domains": ["os_kernel"],
        "enrichment": {"cves": [cve], "products": ["openssl"]},
        "sources": {"primary": [], "secondary": []},
    }


def _day(date_str, cards):
    return {"date_str": date_str, "ts_str": f"{date_str} 06:00 UTC", "cards": cards}


# ── _compute_weekly_cross_run ─────────────────────────────────────────────────

class TestComputeWeeklyCrossRun:
    def test_returns_empty_for_single_day(self):
        days = [_day("2026-03-18", [_card()])]
        assert _compute_weekly_cross_run(days) == {}

    def test_returns_empty_for_no_days(self):
        assert _compute_weekly_cross_run([]) == {}

    def test_still_active_counts_matching_unresolved_cards(self):
        # Same CVE in oldest and today → still active
        old = _day("2026-03-12", [_card("CVE-2026-1111")])
        today = _day("2026-03-18", [_card("CVE-2026-1111", shelf_resolved=False)])
        result = _compute_weekly_cross_run([today, old])
        assert result["still_active"] == 1
        assert result["history_total"] == 1

    def test_still_active_excludes_resolved_in_today(self):
        old = _day("2026-03-12", [_card("CVE-2026-2222")])
        today = _day("2026-03-18", [_card("CVE-2026-2222", shelf_resolved=True)])
        result = _compute_weekly_cross_run([today, old])
        assert result["still_active"] == 0

    def test_still_active_excludes_resolved_in_oldest(self):
        old = _day("2026-03-12", [_card("CVE-2026-3333", shelf_resolved=True)])
        today = _day("2026-03-18", [_card("CVE-2026-3333", shelf_resolved=False)])
        result = _compute_weekly_cross_run([today, old])
        # Old card was already resolved — skip it
        assert result["still_active"] == 0

    def test_still_active_zero_when_no_overlap(self):
        old = _day("2026-03-12", [_card("CVE-2026-0001")])
        today = _day("2026-03-18", [_card("CVE-2026-9999")])
        result = _compute_weekly_cross_run([today, old])
        assert result["still_active"] == 0
        assert result["history_total"] == 1

    def test_history_date_is_oldest_day(self):
        days = [
            _day("2026-03-18", [_card("CVE-2026-1")]),
            _day("2026-03-15", [_card("CVE-2026-2")]),
            _day("2026-03-12", [_card("CVE-2026-3")]),
        ]
        result = _compute_weekly_cross_run(days)
        assert result["history_date"] == "2026-03-12"

    def test_patch_improved_counts_no_fix_to_patched(self):
        # Oldest: no_fix — newest: patched — same CVE
        old = _day("2026-03-12", [_card("CVE-2026-5555", patch="no_fix")])
        today = _day("2026-03-18", [_card("CVE-2026-5555", patch="patched")])
        result = _compute_weekly_cross_run([today, old])
        assert result["patch_improved"] == 1

    def test_patch_improved_counts_no_fix_to_workaround(self):
        old = _day("2026-03-12", [_card("CVE-2026-6666", patch="no_fix")])
        today = _day("2026-03-18", [_card("CVE-2026-6666", patch="workaround")])
        result = _compute_weekly_cross_run([today, old])
        assert result["patch_improved"] == 1

    def test_patch_improved_zero_for_no_status_change(self):
        old = _day("2026-03-12", [_card("CVE-2026-7777", patch="no_fix")])
        today = _day("2026-03-18", [_card("CVE-2026-7777", patch="no_fix")])
        result = _compute_weekly_cross_run([today, old])
        assert result["patch_improved"] == 0

    def test_patch_improved_zero_for_already_patched(self):
        # Was patched all along — not an improvement
        old = _day("2026-03-12", [_card("CVE-2026-8888", patch="patched")])
        today = _day("2026-03-18", [_card("CVE-2026-8888", patch="patched")])
        result = _compute_weekly_cross_run([today, old])
        assert result["patch_improved"] == 0

    def test_multiple_cves_tracked_independently(self):
        old = _day("2026-03-12", [
            _card("CVE-2026-A", patch="no_fix"),
            _card("CVE-2026-B", patch="no_fix"),
            _card("CVE-2026-C", patch="unknown"),
        ])
        today = _day("2026-03-18", [
            _card("CVE-2026-A", patch="patched"),
            _card("CVE-2026-B", patch="no_fix"),
            _card("CVE-2026-C", patch="patched"),
        ])
        result = _compute_weekly_cross_run([today, old])
        assert result["patch_improved"] == 1  # only A went no_fix → patched


# ── _annotate_history_lifecycle ───────────────────────────────────────────────

class TestAnnotateHistoryLifecycle:
    def _map(self, cards):
        """Build current_card_map as runner.py does."""
        from agent.runner import _shelf_key
        return {_shelf_key(c): c for c in cards}

    def test_still_active_counted(self):
        card = _card("CVE-2026-1111", shelf_resolved=False)
        current_map = self._map([card])
        days = [_day("2026-03-17", [_card("CVE-2026-1111")])]
        annotated = _annotate_history_lifecycle(days, current_map)
        assert annotated[0]["still_active"] == 1
        assert annotated[0]["resolved"] == 0

    def test_resolved_counted(self):
        card = _card("CVE-2026-2222", shelf_resolved=True)
        current_map = self._map([card])
        days = [_day("2026-03-17", [_card("CVE-2026-2222")])]
        annotated = _annotate_history_lifecycle(days, current_map)
        assert annotated[0]["resolved"] == 1
        assert annotated[0]["still_active"] == 0

    def test_escalated_counted_when_risk_increased(self):
        current = _card("CVE-2026-3333", risk=90, shelf_resolved=False)
        current_map = self._map([current])
        old = _card("CVE-2026-3333", risk=60)
        days = [_day("2026-03-17", [old])]
        annotated = _annotate_history_lifecycle(days, current_map)
        assert annotated[0]["escalated"] == 1

    def test_escalated_not_counted_when_risk_unchanged_or_decreased(self):
        current = _card("CVE-2026-4444", risk=60, shelf_resolved=False)
        current_map = self._map([current])
        old = _card("CVE-2026-4444", risk=80)
        days = [_day("2026-03-17", [old])]
        annotated = _annotate_history_lifecycle(days, current_map)
        assert annotated[0]["escalated"] == 0

    def test_unknown_cards_not_counted(self):
        """Old card with no match in current_card_map is silently skipped."""
        current_map = self._map([_card("CVE-2026-9999")])
        days = [_day("2026-03-17", [_card("CVE-2026-0000")])]
        annotated = _annotate_history_lifecycle(days, current_map)
        assert annotated[0]["still_active"] == 0
        assert annotated[0]["resolved"] == 0
        assert annotated[0]["escalated"] == 0

    def test_original_day_fields_preserved(self):
        current_map = self._map([])
        days = [_day("2026-03-17", [_card()])]
        annotated = _annotate_history_lifecycle(days, current_map)
        assert annotated[0]["date_str"] == "2026-03-17"
        assert annotated[0]["ts_str"] == "2026-03-17 06:00 UTC"

    def test_empty_days_returns_empty(self):
        assert _annotate_history_lifecycle([], {}) == []


# ── _build_velocity_sparkline ─────────────────────────────────────────────────

class TestBuildVelocitySparkline:
    def test_returns_empty_for_no_data(self):
        assert _build_velocity_sparkline({}) == ""

    def test_returns_svg(self):
        out = _build_velocity_sparkline({"2026-03-18": 3})
        assert out.startswith("<svg")
        assert "polyline" in out

    def test_always_seven_slots(self):
        # Only one day provided — should still produce 7 data points
        out = _build_velocity_sparkline({"2026-03-18": 5})
        # 7 circles: 6 empty + 1 filled
        assert out.count("<circle") == 7

    def test_full_week_seven_slots(self):
        counts = {f"2026-03-{12+i:02d}": i + 1 for i in range(7)}
        out = _build_velocity_sparkline(counts)
        assert out.count("<circle") == 7

    def test_zero_count_days_transparent(self):
        out = _build_velocity_sparkline({"2026-03-18": 0})
        assert "transparent" in out

    def test_nonzero_count_days_filled(self):
        out = _build_velocity_sparkline({"2026-03-18": 3})
        assert "var(--vel-dot,#60a5fa)" in out


# ── _build_weekly_section cross-run tiles ────────────────────────────────────

class TestWeeklySectionCrossRunTiles:
    _BASE_AGG = {
        "total_cards": 8,
        "unique_cves": 5,
        "active_domains": ["os_kernel", "cloud_iam"],
        "most_active_day": "2026-03-18",
        "window_days": 5,
        "day_counts": {"2026-03-14": 2, "2026-03-15": 3, "2026-03-18": 3},
        "top_cves": [],
        "weekly_summary": "",
    }

    def test_still_active_tile_shown_with_cross_run(self):
        wcr = {"still_active": 3, "history_total": 7, "history_date": "2026-03-12", "patch_improved": 0}
        out = _build_weekly_section(self._BASE_AGG, cross_run=wcr)
        assert "Still Active" in out
        assert "3" in out
        assert "/7" in out
        assert "2026-03-12" in out

    def test_total_findings_fallback_without_cross_run(self):
        out = _build_weekly_section(self._BASE_AGG, cross_run=None)
        assert "Total Findings" in out
        assert "Still Active" not in out

    def test_total_findings_fallback_when_history_total_zero(self):
        out = _build_weekly_section(self._BASE_AGG, cross_run={"still_active": 0, "history_total": 0, "patch_improved": 0})
        assert "Total Findings" in out

    def test_patched_this_week_tile_shown_when_positive(self):
        wcr = {"still_active": 2, "history_total": 5, "history_date": "2026-03-12", "patch_improved": 2}
        out = _build_weekly_section(self._BASE_AGG, cross_run=wcr)
        assert "Patched This Week" in out
        assert "+2" in out
        assert "wkpi--good" in out

    def test_patched_this_week_shows_dash_when_zero(self):
        wcr = {"still_active": 0, "history_total": 5, "history_date": "2026-03-12", "patch_improved": 0}
        out = _build_weekly_section(self._BASE_AGG, cross_run=wcr)
        assert "Patched This Week" in out
        assert "no change" in out

    def test_threat_velocity_sparkline_present(self):
        out = _build_weekly_section(self._BASE_AGG)
        assert "Threat Velocity" in out
        assert "vel-spark" in out

    def test_unique_cves_tile_always_present(self):
        out = _build_weekly_section(self._BASE_AGG)
        assert "Unique CVEs" in out
        assert "5" in out

    def test_most_active_day_tile_always_present(self):
        out = _build_weekly_section(self._BASE_AGG)
        assert "Most Active Day" in out
        assert "2026-03-18" in out

    def test_empty_aggregate_returns_empty(self):
        assert _build_weekly_section({}) == ""
        assert _build_weekly_section({"total_cards": 0}) == ""


# ── _build_history_accordion lifecycle badges ─────────────────────────────────

class TestHistoryAccordionLifecycleBadges:
    def _annotated_day(self, still_active=0, resolved=0, escalated=0):
        return {
            "date_str": "2026-03-17",
            "ts_str": "2026-03-17 06:00 UTC",
            "cards": [_card()],
            "still_active": still_active,
            "resolved": resolved,
            "escalated": escalated,
        }

    def test_active_badge_shown(self):
        out = _build_history_accordion([self._annotated_day(still_active=2)])
        assert "ha-lc--active" in out
        assert "2 active" in out

    def test_resolved_badge_shown(self):
        out = _build_history_accordion([self._annotated_day(resolved=1)])
        assert "ha-lc--resolved" in out
        assert "1 resolved" in out

    def test_escalated_badge_shown(self):
        out = _build_history_accordion([self._annotated_day(escalated=1)])
        assert "ha-lc--escalated" in out
        assert "1 escalated" in out

    def test_no_badges_when_all_zero(self):
        out = _build_history_accordion([self._annotated_day(0, 0, 0)])
        assert "ha-lc" not in out

    def test_no_badges_when_lifecycle_keys_absent(self):
        # Day without annotation keys — pre-annotate path not run
        day = {"date_str": "2026-03-17", "ts_str": "2026-03-17 06:00 UTC", "cards": [_card()]}
        out = _build_history_accordion([day])
        assert "ha-lifecycle" not in out

    def test_multiple_badges_in_same_day(self):
        out = _build_history_accordion([self._annotated_day(still_active=3, resolved=1, escalated=2)])
        assert "ha-lc--active" in out
        assert "ha-lc--resolved" in out
        assert "ha-lc--escalated" in out

    def test_existing_meta_still_present(self):
        out = _build_history_accordion([self._annotated_day(still_active=1)])
        assert "finding" in out
        assert "2026-03-17" in out
