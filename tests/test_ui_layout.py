"""UI layout/regression tests for report HTML generation in agent.runner."""

import pytest

from agent.runner import _write_index_html, build_domain_heatmap

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
