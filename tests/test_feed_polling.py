"""
Tests for feed-polling functions using mocked HTTP responses.

All network I/O is intercepted — no real HTTP calls are made.
"""

import pytest
from unittest.mock import MagicMock, patch

from agent.runner import _poll_cisa_kev, add_ignore, deduplicate, item_hash

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

RECENT_DATE = "2026-03-04"  # Within any reasonable since_hours window
OLD_DATE = "2024-01-01"  # Always outside the window

SAMPLE_KEV_PAYLOAD = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1001",
            "vulnerabilityName": "OpenSSL Heap Overflow RCE",
            "dateAdded": RECENT_DATE,
            "shortDescription": "Critical heap overflow allows RCE via malformed TLS.",
        },
        {
            "cveID": "CVE-2024-0001",
            "vulnerabilityName": "Old Stale Vulnerability",
            "dateAdded": OLD_DATE,
            "shortDescription": "Patched years ago.",
        },
    ]
}


def _make_mock_response(payload: dict) -> MagicMock:
    r = MagicMock()
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


# ---------------------------------------------------------------------------
# _poll_cisa_kev
# ---------------------------------------------------------------------------


class TestPollCisaKev:
    def test_returns_items_within_lookback_window(self, empty_ignore):
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(SAMPLE_KEV_PAYLOAD)
            items = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=48
            )
        titles = [it["title"] for it in items]
        assert any("CVE-2026-1001" in t for t in titles)

    def test_filters_out_entries_older_than_window(self, empty_ignore):
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(SAMPLE_KEV_PAYLOAD)
            items = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=48
            )
        titles = [it["title"] for it in items]
        assert not any("CVE-2024-0001" in t for t in titles)

    def test_respects_ignore_list(self, empty_ignore):
        add_ignore(
            empty_ignore,
            "url",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
            ttl_days=7,
        )
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(SAMPLE_KEV_PAYLOAD)
            items = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=48
            )
        assert not any("CVE-2026-1001" in it["title"] for it in items)

    def test_empty_feed_returns_empty_list(self, empty_ignore):
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response({"vulnerabilities": []})
            items = _poll_cisa_kev("https://www.cisa.gov/kev.json", empty_ignore)
        assert items == []

    def test_item_has_required_fields(self, empty_ignore):
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(SAMPLE_KEV_PAYLOAD)
            items = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=48
            )
        assert len(items) >= 1
        for item in items:
            assert "title" in item
            assert "url" in item
            assert "summary" in item
            assert "published_at" in item

    def test_url_points_to_nvd_detail_page(self, empty_ignore):
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(SAMPLE_KEV_PAYLOAD)
            items = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=48
            )
        for item in items:
            assert item["url"].startswith("https://nvd.nist.gov/vuln/detail/")

    def test_invalid_date_format_does_not_raise(self, empty_ignore):
        """A malformed dateAdded should be included rather than crash."""
        payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-9999",
                    "vulnerabilityName": "Test",
                    "dateAdded": "not-a-date",
                    "shortDescription": "Broken date field",
                }
            ]
        }
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(payload)
            # Must not raise
            items = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=24
            )
        # Item passes through when date parsing fails gracefully
        assert any("CVE-2026-9999" in it["title"] for it in items)


# ---------------------------------------------------------------------------
# Cross-function: poll → deduplicate round-trip
# ---------------------------------------------------------------------------


class TestPollAndDedup:
    def test_second_poll_of_same_cve_is_deduplicated(self, empty_ignore):
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(SAMPLE_KEV_PAYLOAD)
            first = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=48
            )

        fresh1, seen = deduplicate(first, set())
        assert len(fresh1) >= 1

        # Simulate a second identical poll
        with patch("agent.runner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(SAMPLE_KEV_PAYLOAD)
            second = _poll_cisa_kev(
                "https://www.cisa.gov/kev.json", empty_ignore, since_hours=48
            )

        fresh2, _ = deduplicate(second, seen)
        assert len(fresh2) == 0, "No new items should pass deduplication on second poll"
