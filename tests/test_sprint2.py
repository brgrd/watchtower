"""Tests for Sprint 2: CVE Timeline (Forensics) and Remediation Tracker.

Covers:
  - _build_forensics_html() CVE Timeline panel (Panel E)
    - history_days=None → no timeline section
    - history_days with single day → no timeline rows (< 2 days)
    - history_days with 2+ days → timeline rows rendered
    - Patch progression only emits entries on status change
    - Finding references grouped by day
    - CVE only in current window (1 history day) still appears if in cve_map
  - _write_index_html() Remediation Tracker
    - rem-pill button present on every card
    - rem-pill has correct data-card-id
    - CSS states present (.rem-pill, .cluster[data-rem-state=...])
    - initRemediationTracker JS present
    - remCycle JS present
    - wt.remediation localStorage key used
"""

import pytest

from agent.html_builder import _build_forensics_html, _write_index_html

pytestmark = pytest.mark.unit


# ── Shared helpers ──────────────────────────────────────────────────────────────

def _card(cve="CVE-2026-1111", risk=70, patch="no_fix", shelf_resolved=False,
          run_count=1, title=None):
    return {
        "id": f"card-{cve}",
        "title": title or f"Vuln in openssl ({cve})",
        "summary": f"Critical issue tracked as {cve}.",
        "risk_score": risk,
        "priority": "P1",
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


def _minimal_write_kwargs(cards):
    """Minimal kwargs for _write_index_html that won't error."""
    return dict(
        path="/dev/null",
        cards=cards,
        heatmap={},
        ts="2026-03-18_06-00",
        executive="",
        history=[],
        since_hours=6,
        groq_status="ok",
        delta=None,
        history_days=[],
        weekly_html="",
        feed_health={},
        run_metrics=None,
        feed_run_metrics=None,
        velocity=None,
        ioc_ledger={},
    )


# ── CVE Timeline — _build_forensics_html ───────────────────────────────────────

class TestCveTimeline:
    def test_no_history_no_timeline_section(self):
        cards = [_card()]
        out = _build_forensics_html(cards, history_days=None)
        assert "CVE Timeline" not in out

    def test_empty_history_no_timeline_section(self):
        out = _build_forensics_html([_card()], history_days=[])
        assert "CVE Timeline" not in out

    def test_single_history_day_shows_empty_message(self):
        """Single day → no row qualifies (< 2 days) unless in current cards."""
        # CVE not in current cards → no row
        cards = [_card("CVE-2026-XXXX")]
        days = [_day("2026-03-17", [_card("CVE-2026-ZZZZ")])]  # different CVE
        out = _build_forensics_html(cards, history_days=days)
        assert "CVE Timeline" in out
        assert "No cross-run CVE history available yet" in out

    def test_two_days_same_cve_produces_row(self):
        cve = "CVE-2026-1111"
        days = [
            _day("2026-03-18", [_card(cve)]),
            _day("2026-03-17", [_card(cve)]),
        ]
        out = _build_forensics_html([_card(cve)], history_days=days)
        assert "CVE Timeline" in out
        assert cve in out
        assert "2d tracked" in out

    def test_patch_progression_emitted_on_status_change(self):
        cve = "CVE-2026-2222"
        days = [
            _day("2026-03-18", [_card(cve, patch="patched")]),
            _day("2026-03-17", [_card(cve, patch="no_fix")]),
        ]
        out = _build_forensics_html([_card(cve, patch="patched")], history_days=days)
        # Should show both statuses in progression
        assert "No Fix" in out
        assert "Patched" in out

    def test_no_progression_when_status_unchanged(self):
        cve = "CVE-2026-3333"
        days = [
            _day("2026-03-18", [_card(cve, patch="no_fix")]),
            _day("2026-03-17", [_card(cve, patch="no_fix")]),
        ]
        out = _build_forensics_html([_card(cve)], history_days=days)
        # cve-tl-prog only appears when there are 2+ progression items
        # (only one status emitted → prog_html is empty)
        assert "cve-tl-prog" not in out

    def test_finding_titles_in_day_refs(self):
        cve = "CVE-2026-4444"
        days = [
            _day("2026-03-18", [_card(cve, title="Alpha finding")]),
            _day("2026-03-17", [_card(cve, title="Beta finding")]),
        ]
        out = _build_forensics_html([_card(cve)], history_days=days)
        assert "Alpha finding" in out
        assert "Beta finding" in out

    def test_cve_only_in_current_window_with_one_history_day(self):
        """CVE with 1 history day but present in current cards is included."""
        cve = "CVE-2026-5555"
        current = _card(cve)  # in current window
        days = [_day("2026-03-17", [_card(cve)])]  # only 1 history day
        out = _build_forensics_html([current], history_days=days)
        assert cve in out

    def test_cve_not_in_current_and_single_day_excluded(self):
        """CVE with only 1 history day and absent from current window → excluded."""
        current_cve = "CVE-2026-AAAA"
        old_cve = "CVE-2026-BBBB"
        days = [_day("2026-03-17", [_card(old_cve)])]
        out = _build_forensics_html([_card(current_cve)], history_days=days)
        assert old_cve not in out

    def test_nvd_link_present(self):
        cve = "CVE-2026-6666"
        days = [
            _day("2026-03-18", [_card(cve)]),
            _day("2026-03-17", [_card(cve)]),
        ]
        out = _build_forensics_html([_card(cve)], history_days=days)
        assert f"nvd.nist.gov/vuln/detail/{cve}" in out

    def test_history_days_newest_first_order_handled(self):
        """history_days is newest-first; timeline should still show oldest first_seen."""
        cve = "CVE-2026-7777"
        days = [
            _day("2026-03-18", [_card(cve)]),  # newest first
            _day("2026-03-15", [_card(cve)]),
            _day("2026-03-12", [_card(cve)]),  # oldest
        ]
        out = _build_forensics_html([_card(cve)], history_days=days)
        assert "3d tracked" in out

    def test_empty_cards_with_history(self):
        """No current cards but history_days still builds timeline for multi-day CVEs."""
        cve = "CVE-2026-8888"
        days = [
            _day("2026-03-18", [_card(cve)]),
            _day("2026-03-17", [_card(cve)]),
        ]
        out = _build_forensics_html([], history_days=days)
        assert cve in out


# ── Remediation Tracker — _write_index_html ────────────────────────────────────

class TestRemediationTracker:
    def _render(self, cards=None):
        if cards is None:
            cards = [_card()]
        kwargs = _minimal_write_kwargs(cards)
        out_parts = []
        # Capture output by monkeypatching open
        import builtins
        original_open = builtins.open
        class _Capture:
            def __init__(self): self.content = ""
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def write(self, s): self.content += s
        cap = _Capture()
        def _fake_open(path, mode="r", **kw):
            if "w" in mode and (path == "/dev/null" or path.replace("\\", "/").startswith("/dev/")):
                return cap
            return original_open(path, mode, **kw)
        import unittest.mock as mock
        with mock.patch("builtins.open", _fake_open):
            _write_index_html(**kwargs)
        return cap.content

    def test_rem_pill_present_on_card(self):
        out = self._render([_card("CVE-2026-1111")])
        assert 'class="rem-pill"' in out

    def test_rem_pill_data_card_id_matches_card(self):
        cve = "CVE-2026-2222"
        out = self._render([_card(cve)])
        assert f'data-card-id="card-{cve}"' in out

    def test_rem_pill_count_matches_card_count(self):
        cards = [_card("CVE-2026-A"), _card("CVE-2026-B"), _card("CVE-2026-C")]
        out = self._render(cards)
        assert out.count('class="rem-pill"') == 3

    def test_rem_css_base_class_present(self):
        out = self._render()
        assert ".rem-pill{" in out

    def test_rem_css_inprog_state_present(self):
        out = self._render()
        assert 'data-rem-state="inprog"' in out or "inprog" in out

    def test_rem_css_mitigated_state_present(self):
        out = self._render()
        assert "mitigated" in out

    def test_init_remediation_tracker_js_present(self):
        out = self._render()
        assert "initRemediationTracker" in out

    def test_rem_cycle_js_present(self):
        out = self._render()
        assert "remCycle" in out

    def test_wt_remediation_localstorage_key_used(self):
        out = self._render()
        assert "wt.remediation" in out

    def test_rem_update_alerts_js_present(self):
        out = self._render()
        assert "_remUpdateAlerts" in out

    def test_rem_pill_onclick_stops_propagation(self):
        out = self._render()
        assert "stopPropagation" in out
