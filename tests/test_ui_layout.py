"""UI layout/regression tests for report HTML generation in agent.runner."""

import pytest

from agent.runner import _write_index_html, build_domain_heatmap
from agent.html_builder import _build_alerts_html, _build_priority_actions_html

pytestmark = pytest.mark.unit


def _sample_cards() -> list[dict]:
    return [
        {
            "id": "card-a",
            "title": "CVE-2026-3823 in container runtime",
            "summary": "Kernel/container boundary issue with active exploit chatter.",
            "risk_score": 88,
            "priority": "P1",
            "domains": ["container", "os_kernel"],
            "sources": {
                "primary": [
                    {
                        "title": "NVD CVE-2026-3823",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-3823",
                    }
                ],
                "secondary": [],
            },
            "recommended_actions_24h": ["Patch runtime", "Restart affected nodes"],
            "recommended_actions_7d": ["Complete fleet audit"],
            "patch_status": "unknown",
            "confidence": 0.91,
        },
        {
            "id": "card-b",
            "title": "Browser extension supply-chain concern",
            "summary": "Malicious update path observed in extension ecosystem.",
            "risk_score": 64,
            "priority": "P2",
            "domains": ["browser_ext", "supply_chain"],
            "sources": {
                "primary": [
                    {
                        "title": "Vendor advisory",
                        "url": "https://example.com/advisory/browser-extension-update",
                    }
                ],
                "secondary": [],
            },
            "recommended_actions_24h": ["Block extension ID"],
            "recommended_actions_7d": ["Review extension policy"],
            "patch_status": "workaround",
            "confidence": 0.72,
        },
    ]


def _render_html(tmp_path) -> str:
    cards = _sample_cards()
    heatmap = build_domain_heatmap(cards)
    out = tmp_path / "index.html"
    _write_index_html(
        path=str(out),
        cards=cards,
        heatmap=heatmap,
        ts="2026-03-09_07-40",
        executive="",
        history=[],
        since_hours=24,
        groq_status="ok",
        delta={"new": [], "elevated": [], "resolved": []},
        history_days=[],
        weekly_html="",
    )
    return out.read_text(encoding="utf-8")


class TestAnchoredRailLayout:
    def test_generates_fixed_right_rail_structure(self, tmp_path):
        html = _render_html(tmp_path)
        assert 'id="domain-rail"' in html
        assert 'class="panel right-rail"' in html
        assert 'id="rail-handle"' in html
        assert 'class="app-main"' in html
        assert 'class="threat-side"' not in html

    def test_generates_module_tabs_and_panels(self, tmp_path):
        html = _render_html(tmp_path)
        assert 'id="tab-overview"' in html
        assert 'id="tab-feeds"' in html
        assert 'id="tab-alerts"' in html
        assert 'id="tab-forensics"' in html
        assert 'id="panel-overview"' in html
        assert 'id="panel-feeds"' in html
        assert 'id="panel-alerts"' in html
        assert 'id="panel-forensics"' in html


class TestRailBehaviorHooks:
    def test_contains_persistence_and_resize_logic(self, tmp_path):
        html = _render_html(tmp_path)
        assert "wt.rail.width" in html
        assert "wt.rail.collapsed" in html
        assert "wt.rail.tab" in html
        assert "applyRailWidth" in html
        assert "setRailCollapsed" in html
        assert "pointerdown" in html

    def test_contains_telemetry_and_mobile_controls(self, tmp_path):
        html = _render_html(tmp_path)
        assert "WT_TELEMETRY" in html
        assert "trackUi(" in html
        assert "rail_resize_start" in html
        assert "rail_resized" in html
        assert 'id="rail-mobile-toggle"' in html
        assert 'id="rail-backdrop"' in html


class TestAlertsTab:
    def test_placeholder_removed(self, tmp_path):
        html = _render_html(tmp_path)
        assert "Reserved module slot" not in html

    def test_three_section_headers_present(self, tmp_path):
        # With no persistent/elevated cards the placeholder text is shown instead
        html = _render_html(tmp_path)
        assert "P1 / Attribution" in html
        # Persistent and Elevated headers are omitted when empty; a combined
        # quiet message is shown instead
        assert "No persistent or elevated alerts this run" in html

    def test_persistent_header_shown_when_populated(self):
        from agent.html_builder import _build_alerts_html
        cards = [
            {
                "id": "p1a", "title": "Persistent finding", "risk_score": 80,
                "priority": "P1", "domains": ["os_kernel"],
                "sources": {"primary": [], "secondary": []},
                "run_count": 5,
            }
        ]
        out = _build_alerts_html(cards, {})
        assert "Persistent" in out
        assert "No persistent or elevated alerts" not in out

    def test_elevated_header_shown_when_populated(self):
        from agent.html_builder import _build_alerts_html
        elevated_card = {
            "id": "elev1", "title": "Elevated finding", "risk_score": 70,
            "priority": "P2", "domains": ["os_kernel"],
            "sources": {"primary": [], "secondary": []},
            "run_count": 1, "_score_delta": 15,
        }
        out = _build_alerts_html([], {"elevated": [elevated_card]})
        assert "Elevated" in out
        assert "No persistent or elevated alerts" not in out

    def test_p1_card_appears_in_p1_section(self):
        cards = [
            {
                "id": "p1-card",
                "title": "Critical exploit in the wild",
                "risk_score": 90,
                "priority": "P1",
                "domains": ["os_kernel"],
                "sources": {"primary": [], "secondary": []},
            }
        ]
        out = _build_alerts_html(cards, {})
        assert "P1 / Attribution" in out
        assert "alert-annot--p1" in out
        assert "Critical exploit in the wild" in out

    def test_persistent_card_appears_with_run_count_badge(self):
        cards = [
            {
                "id": "persist-card",
                "title": "Long-running threat actor campaign",
                "risk_score": 72,
                "priority": "P2",
                "domains": ["network"],
                "run_count": 5,
                "sources": {"primary": [], "secondary": []},
            }
        ]
        out = _build_alerts_html(cards, {})
        assert "Seen 5 runs" in out
        assert "alert-annot--persist" in out

    def test_elevated_card_uses_delta_score(self):
        elevated_card = {
            "id": "elev-card",
            "title": "Escalating ransomware campaign",
            "risk_score": 85,
            "priority": "P2",
            "domains": ["ransomware"],
            "_score_delta": 15,
            "sources": {"primary": [], "secondary": []},
        }
        out = _build_alerts_html([], {"elevated": [elevated_card]})
        assert "+15 ↑" in out
        assert "alert-annot--elevated" in out

    def test_attribution_flag_shows_attr_badge(self):
        cards = [
            {
                "id": "attr-card",
                "title": "Nation-state actor attributed campaign",
                "risk_score": 78,
                "priority": "P2",
                "domains": ["nation_state"],
                "attribution_flag": True,
                "sources": {"primary": [], "secondary": []},
            }
        ]
        out = _build_alerts_html(cards, {})
        assert "⚠ Attr" in out
        assert "alert-annot--attr" in out

    def test_empty_sections_show_none_message(self):
        out = _build_alerts_html([], {})
        assert "None this run" in out or "No findings available" in out

    def test_alert_rows_have_data_card_id(self):
        cards = [
            {
                "id": "row-id-check",
                "title": "Some finding",
                "risk_score": 80,
                "priority": "P1",
                "domains": ["cloud_iam"],
                "sources": {"primary": [], "secondary": []},
            }
        ]
        out = _build_alerts_html(cards, {})
        assert 'data-card-id="row-id-check"' in out

    def test_finding_cards_have_html_id(self, tmp_path):
        html = _render_html(tmp_path)
        assert 'id="card-card-a"' in html
        assert 'id="card-card-b"' in html

    def test_scroll_handler_js_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "alert-row" in html
        assert "data-card-id" in html
        assert "alert-highlight" in html


class TestPriorityActionsPanel:
    def _p1_card(self, actions):
        return {
            "id": "pa-card",
            "title": "Critical finding",
            "risk_score": 88,
            "priority": "P1",
            "domains": ["os_kernel"],
            "recommended_actions_24h": actions,
            "sources": {"primary": [], "secondary": []},
        }

    def test_returns_empty_for_no_p1_p2_cards(self):
        cards = [
            {
                "id": "p3",
                "title": "Low signal",
                "risk_score": 20,
                "priority": "P3",
                "domains": [],
                "recommended_actions_24h": ["Do something"],
                "sources": {"primary": [], "secondary": []},
            }
        ]
        assert _build_priority_actions_html(cards) == ""

    def test_renders_actions_from_p1_card(self):
        cards = [self._p1_card(["Patch OpenSSL immediately", "Block outbound 443"])]
        out = _build_priority_actions_html(cards)
        assert "Patch OpenSSL immediately" in out
        assert "Block outbound 443" in out
        assert "pa-panel" in out

    def test_deduplicates_identical_actions_across_cards(self):
        action = "Isolate affected hosts from network"
        cards = [
            self._p1_card([action]),
            {**self._p1_card([action]), "id": "pa-card-2"},
            {**self._p1_card([action]), "id": "pa-card-3"},
        ]
        out = _build_priority_actions_html(cards)
        assert "3×" in out
        assert out.count("Isolate affected hosts") == 1

    def test_count_chip_only_for_multiple_occurrences(self):
        cards = [
            self._p1_card(["Unique action only on one card"]),
        ]
        out = _build_priority_actions_html(cards)
        assert "×" not in out

    def test_capped_at_seven_items(self):
        actions = [f"Action number {i}" for i in range(10)]
        cards = [self._p1_card(actions[:4]), {**self._p1_card(actions[4:8]), "id": "pa-2"}]
        out = _build_priority_actions_html(cards)
        assert out.count("pa-item") <= 7

    def test_panel_present_in_full_render(self, tmp_path):
        html = _render_html(tmp_path)
        # sample cards include a P1 card with recommended_actions_24h
        assert "pa-panel" in html
        assert "Priority Actions" in html


class TestCatchupView:
    def test_catchup_js_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "wt.last_visit" in html
        assert "catchup-strip" in html

    def test_catchup_gap_threshold(self, tmp_path):
        html = _render_html(tmp_path)
        assert "gapH<4" in html

    def test_catchup_filters_by_first_seen_ts(self, tmp_path):
        html = _render_html(tmp_path)
        assert "first_seen_ts" in html
        assert "lvDate" in html

    def test_catchup_rows_have_data_card_id(self, tmp_path):
        html = _render_html(tmp_path)
        assert "cu-row" in html
        assert "data-card-id" in html

    def test_catchup_last_visit_saved_before_check(self, tmp_path):
        html = _render_html(tmp_path)
        save_pos = html.index("localStorage.setItem('wt.last_visit'")
        gap_pos = html.index("gapH<4")
        assert save_pos < gap_pos

    def test_catchup_css_classes_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "catchup-summary" in html
        assert "cu-score" in html
        assert "cu-title" in html
        assert "cu-p1" in html

    def test_catchup_away_label_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "You were away" in html
        assert "here" in html  # "here's what changed"

    def test_catchup_p1_chip_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "cu-chip--p1" in html

    def test_catchup_still_active_chip_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "cu-chip--active" in html
        assert "still active" in html

    def test_catchup_patch_chip_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "cu-chip--patch" in html
        assert "status changed" in html

    def test_catchup_cve_status_snapshot_saved(self, tmp_path):
        html = _render_html(tmp_path)
        assert "wt.cve_status" in html
        assert "cveSnap" in html

    def test_catchup_cve_status_snapshot_saved_before_gap_check(self, tmp_path):
        html = _render_html(tmp_path)
        snap_pos = html.index("wt.cve_status")
        gap_pos = html.index("gapH<4")
        assert snap_pos < gap_pos

    def test_catchup_patch_change_rows_rendered(self, tmp_path):
        html = _render_html(tmp_path)
        assert "cu-patch-row" in html
        assert "cu-patch-cve" in html
        assert "Patch status changes" in html

    def test_catchup_patch_status_classes_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "cu-ps--good" in html
        assert "cu-ps--bad" in html
        assert "cu-ps--warn" in html

    def test_catchup_cards_have_patch_status_and_cves(self, tmp_path):
        html = _render_html(tmp_path)
        # CARDS JS object must expose patch_status, shelf_resolved, cves
        assert '"patch_status"' in html
        assert '"shelf_resolved"' in html
        assert '"cves"' in html

    def test_catchup_section_label_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert "cu-section-label" in html
        assert "New findings" in html


# ─────────────────────────────────────────────────────────────────────────────
# KPI P1 and Exploited delta sub-labels
# ─────────────────────────────────────────────────────────────────────────────


def _p1_card():
    return {
        "id": "delta-p1",
        "title": "CVE-2026-9999 critical kernel exploit",
        "summary": "Critical kernel privilege escalation, actively exploited in the wild.",
        "risk_score": 90,
        "priority": "P1",
        "domains": ["os_kernel"],
        "sources": {"primary": [{"title": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999"}], "secondary": []},
        "patch_status": "unknown",
    }


def _render_with_delta(tmp_path, delta: dict) -> str:
    cards = _sample_cards()
    heatmap = build_domain_heatmap(cards)
    out = tmp_path / "index_delta.html"
    _write_index_html(
        path=str(out),
        cards=cards,
        heatmap=heatmap,
        ts="2026-03-09_07-40",
        executive="",
        history=[],
        since_hours=24,
        groq_status="ok",
        delta=delta,
        history_days=[],
        weekly_html="",
    )
    return out.read_text(encoding="utf-8")


class TestKpiDelta:
    def test_new_p1_shows_up_arrow(self, tmp_path):
        delta = {"new": [_p1_card()], "elevated": [], "resolved": []}
        html = _render_with_delta(tmp_path, delta)
        assert "kpi-delta--up" in html
        assert "+1 ↑" in html

    def test_resolved_p1_shows_down_arrow(self, tmp_path):
        delta = {"new": [], "elevated": [], "resolved": [_p1_card()]}
        html = _render_with_delta(tmp_path, delta)
        assert "kpi-delta--down" in html
        assert "-1 ↓" in html

    def test_no_p1_change_shows_no_delta(self, tmp_path):
        delta = {"new": [], "elevated": [], "resolved": []}
        html = _render_with_delta(tmp_path, delta)
        # No delta span elements should be emitted (CSS class may still be in stylesheet)
        assert 'class="kpi-delta' not in html

    def test_exploited_new_shows_up_arrow(self, tmp_path):
        # _p1_card has "actively exploited in the wild" in summary → _is_exploitish = True
        delta = {"new": [_p1_card()], "elevated": [], "resolved": []}
        html = _render_with_delta(tmp_path, delta)
        assert "kpi-delta--up" in html

    def test_null_delta_renders_no_delta_labels(self, tmp_path):
        cards = _sample_cards()
        heatmap = build_domain_heatmap(cards)
        out = tmp_path / "index_nodelta.html"
        _write_index_html(
            path=str(out),
            cards=cards,
            heatmap=heatmap,
            ts="2026-03-09_07-40",
            executive="",
            history=[],
            since_hours=24,
            groq_status="ok",
            delta=None,
            history_days=[],
            weekly_html="",
        )
        html = out.read_text(encoding="utf-8")
        assert 'class="kpi-delta' not in html

    def test_kpi_delta_css_present(self, tmp_path):
        html = _render_html(tmp_path)
        assert ".kpi-delta{" in html
