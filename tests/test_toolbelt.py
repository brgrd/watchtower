"""
Tests for agent.toolbelt — planner-dispatched action implementations.
"""

import pytest
from unittest.mock import MagicMock, patch

from agent.toolbelt import ALLOWED_CATEGORIES, tool_add_feed

pytestmark = pytest.mark.unit

VALID_HTTPS_URL = "https://www.bleepingcomputer.com/feed/"


def _make_feed_parse_mock(bozo: bool = False, has_entries: bool = True) -> MagicMock:
    return MagicMock(bozo=bozo, entries=[{"title": "item"}] if has_entries else [])


# ---------------------------------------------------------------------------
# tool_add_feed
# ---------------------------------------------------------------------------


class TestToolAddFeed:
    # ── happy path ───────────────────────────────────────────────────────────

    def test_valid_feed_added_successfully(self):
        feeds = []
        with patch(
            "agent.toolbelt.feedparser.parse", return_value=_make_feed_parse_mock()
        ):
            ok, msg = tool_add_feed(VALID_HTTPS_URL, "vulns", feeds, max_new=5)
        assert ok is True
        assert any(f["url"] == VALID_HTTPS_URL for f in feeds)

    def test_new_feed_marked_dynamic(self):
        feeds = []
        with patch(
            "agent.toolbelt.feedparser.parse", return_value=_make_feed_parse_mock()
        ):
            tool_add_feed(VALID_HTTPS_URL, "blog", feeds, max_new=5)
        assert feeds[-1].get("_dynamic") is True

    def test_new_feed_has_required_fields(self):
        feeds = []
        with patch(
            "agent.toolbelt.feedparser.parse", return_value=_make_feed_parse_mock()
        ):
            tool_add_feed(VALID_HTTPS_URL, "advisories", feeds, max_new=5)
        feed = feeds[-1]
        assert "id" in feed
        assert "url" in feed
        assert "category" in feed
        assert feed["enabled"] is True

    @pytest.mark.parametrize("category", sorted(ALLOWED_CATEGORIES))
    def test_all_allowed_categories_accepted(self, category):
        feeds = []
        url = f"https://example-{category}.com/feed"
        with patch(
            "agent.toolbelt.feedparser.parse", return_value=_make_feed_parse_mock()
        ):
            ok, _ = tool_add_feed(url, category, feeds, max_new=10)
        assert ok is True, f"Category '{category}' should have been accepted"

    # ── rejection cases ───────────────────────────────────────────────────────

    def test_non_https_url_rejected(self):
        ok, msg = tool_add_feed(
            "http://insecure.example.com/feed", "vulns", [], max_new=5
        )
        assert ok is False

    def test_plaintext_url_rejected(self):
        ok, msg = tool_add_feed("not-a-url", "vulns", [], max_new=5)
        assert ok is False
        assert "Invalid URL" in msg

    def test_unknown_category_rejected(self):
        ok, msg = tool_add_feed(VALID_HTTPS_URL, "sports_scores", [], max_new=5)
        assert ok is False
        assert "category" in msg.lower() or "Unknown" in msg

    def test_duplicate_feed_rejected(self):
        feeds = [{"url": VALID_HTTPS_URL, "type": "rss"}]
        ok, msg = tool_add_feed(VALID_HTTPS_URL, "vulns", feeds, max_new=5)
        assert ok is False
        assert "already" in msg.lower()

    def test_max_new_budget_exhausted(self):
        feeds = [
            {"url": f"https://dynamic{i}.example.com/feed", "_dynamic": True}
            for i in range(3)
        ]
        ok, msg = tool_add_feed(VALID_HTTPS_URL, "vulns", feeds, max_new=3)
        assert ok is False
        assert "budget" in msg.lower() or "exhausted" in msg.lower()

    def test_invalid_feed_bozo_with_no_entries_rejected(self):
        feeds = []
        with patch(
            "agent.toolbelt.feedparser.parse",
            return_value=_make_feed_parse_mock(bozo=True, has_entries=False),
        ):
            ok, msg = tool_add_feed(VALID_HTTPS_URL, "vulns", feeds, max_new=5)
        assert ok is False
        assert len(feeds) == 0

    def test_feedparser_exception_rejected(self):
        feeds = []
        with patch(
            "agent.toolbelt.feedparser.parse", side_effect=Exception("network error")
        ):
            ok, msg = tool_add_feed(VALID_HTTPS_URL, "vulns", feeds, max_new=5)
        assert ok is False
        assert len(feeds) == 0

    def test_existing_non_dynamic_feeds_not_counted_in_budget(self):
        """Static (config) feeds must not consume the dynamic-feed budget."""
        feeds = [
            {"url": f"https://static{i}.example.com/feed"}  # no _dynamic flag
            for i in range(10)
        ]
        with patch(
            "agent.toolbelt.feedparser.parse", return_value=_make_feed_parse_mock()
        ):
            ok, _ = tool_add_feed(VALID_HTTPS_URL, "blog", feeds, max_new=1)
        assert ok is True

    def test_feed_not_added_when_rejected(self):
        feeds = []
        tool_add_feed("not-a-valid-url!!", "vulns", feeds, max_new=5)
        assert len(feeds) == 0
