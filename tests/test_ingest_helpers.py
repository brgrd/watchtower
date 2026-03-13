"""
Tests for agent.ingest helpers.

Coverage targets:
  - fetch_url: placeholder mode, non-HTTPS rejection, private host rejection
  - add_ignore / is_ignored: URL, domain, and prefix bucket operations
  - _poll_rss: cutoff filtering, ignore integration
  - _enrich_epss: placeholder skip, cache hit, cache miss with API call
"""

import json
import os
import tempfile
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from agent.ingest import (
    _enrich_epss,
    _poll_rss,
    add_ignore,
    fetch_url,
    is_ignored,
)

pytestmark = pytest.mark.unit


# ─────────────────────────────────────────────────────────────────────────────
# fetch_url
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchUrl:
    """fetch_url is always running under WATCHTOWER_PLACEHOLDER_MODE=true in CI
    (set by conftest.py), so the network is never touched in these tests."""

    def test_placeholder_mode_returns_sentinel(self):
        text = fetch_url("https://example.com/advisory")
        assert text == "placeholder content"

    def test_non_https_raises(self):
        # Turn off placeholder mode so the real validation path runs.
        with patch("agent.ingest.placeholder_mode", return_value=False):
            with pytest.raises((ValueError, Exception)):
                fetch_url("http://example.com/article")

    def test_private_host_raises(self):
        with patch("agent.ingest.placeholder_mode", return_value=False):
            with pytest.raises((ValueError, Exception)):
                fetch_url("https://192.168.1.1/secret")

    def test_returns_string(self):
        result = fetch_url("https://example.com/advisory")
        assert isinstance(result, str)


# ─────────────────────────────────────────────────────────────────────────────
# add_ignore / is_ignored
# ─────────────────────────────────────────────────────────────────────────────


def _fresh_ignore() -> dict:
    """Return a blank ignore state dict."""
    return {
        "ignore_url": {},
        "ignore_domain": {},
        "ignore_url_prefix": {},
    }


class TestAddIgnore:
    def test_add_url_stores_ttl(self):
        ig = _fresh_ignore()
        add_ignore(ig, "url", "https://evil.com/path", 30)
        assert "https://evil.com/path" in ig["ignore_url"]

    def test_add_domain_stores_ttl(self):
        ig = _fresh_ignore()
        add_ignore(ig, "domain", "evil.com", 7)
        assert "evil.com" in ig["ignore_domain"]

    def test_add_prefix_stores_ttl(self):
        ig = _fresh_ignore()
        add_ignore(ig, "url_prefix", "https://spam.example.com/", 14)
        assert "https://spam.example.com/" in ig["ignore_url_prefix"]

    def test_ttl_value_is_iso_date_string(self):
        ig = _fresh_ignore()
        add_ignore(ig, "url", "https://example.com/page", 30)
        value = ig["ignore_url"]["https://example.com/page"]
        # Accept either a plain ISO date "YYYY-MM-DD" or an ISO datetime string
        assert len(value) >= 10
        assert value[4] == "-" and value[7] == "-"

    def test_zero_ttl_still_stores(self):
        ig = _fresh_ignore()
        add_ignore(ig, "domain", "zero.example.com", 0)
        assert "zero.example.com" in ig["ignore_domain"]

    def test_unknown_type_does_not_raise(self):
        ig = _fresh_ignore()
        add_ignore(ig, "nonexistent_type", "value", 30)
        # Should silently ignore or raise a known exception; must NOT crash caller


class TestIsIgnored:
    def test_exact_url_match(self):
        ig = _fresh_ignore()
        add_ignore(ig, "url", "https://evil.com/path", 30)
        assert is_ignored(ig, "https://evil.com/path")

    def test_domain_match(self):
        ig = _fresh_ignore()
        add_ignore(ig, "domain", "evil.com", 30)
        assert is_ignored(ig, "https://evil.com/some/path?q=1")

    def test_prefix_match(self):
        ig = _fresh_ignore()
        add_ignore(ig, "url_prefix", "https://spam.example.com/", 30)
        assert is_ignored(ig, "https://spam.example.com/article/1234")

    def test_no_match_returns_false(self):
        ig = _fresh_ignore()
        assert not is_ignored(ig, "https://safe.example.com/news")

    def test_empty_ignore_never_blocks(self):
        assert not is_ignored(_fresh_ignore(), "https://everything.is.fine/")

    def test_subdomain_not_confused_with_domain(self):
        ig = _fresh_ignore()
        add_ignore(ig, "domain", "evil.com", 30)
        # noevil.com should NOT be blocked
        assert not is_ignored(ig, "https://noevil.com/page")


# ─────────────────────────────────────────────────────────────────────────────
# _poll_rss
# ─────────────────────────────────────────────────────────────────────────────

# feedparser entry shape returned by feedparser.parse()
def _make_fp_entry(link, title, published):
    e = MagicMock()
    e.link = link
    e.title = title
    e.get = lambda k, default="": title if k == "title" else (published if k == "published" else default)
    e.published = published
    return e


class TestPollRss:
    @pytest.fixture(autouse=True)
    def patch_feedparser(self):
        """Patch feedparser.parse to return synthetic feed without network."""
        mock_feed = MagicMock()
        entry_new = _make_fp_entry(
            link="https://feed.example.com/article/new",
            title="New Article",
            published="Mon, 01 Jan 2026 12:00:00 GMT",
        )
        entry_old = _make_fp_entry(
            link="https://feed.example.com/article/old",
            title="Old Article",
            published="Mon, 01 Jan 2020 12:00:00 GMT",
        )
        mock_feed.entries = [entry_new, entry_old]
        mock_feed.bozo = False

        with patch("agent.ingest.feedparser") as mock_fp:
            mock_fp.parse.return_value = mock_feed
            self.mock_feedparser = mock_fp
            yield

    def test_returns_list(self):
        result = _poll_rss("https://feeds.example.com/rss", since_hours=24, ignore=_fresh_ignore())
        assert isinstance(result, list)

    def test_old_entries_excluded_by_cutoff(self):
        result = _poll_rss("https://feeds.example.com/rss", since_hours=24 * 365, ignore=_fresh_ignore())
        urls = [item.get("url") or item.get("link") for item in result]
        assert "https://feed.example.com/article/old" not in urls

    def test_ignored_url_excluded(self):
        ig = _fresh_ignore()
        add_ignore(ig, "url", "https://feed.example.com/article/new", 30)
        result = _poll_rss("https://feeds.example.com/rss", since_hours=24 * 365, ignore=ig)
        urls = [item.get("url") or item.get("link") for item in result]
        assert "https://feed.example.com/article/new" not in urls

    def test_ignored_domain_excludes_all_entries(self):
        ig = _fresh_ignore()
        add_ignore(ig, "domain", "feed.example.com", 30)
        result = _poll_rss("https://feeds.example.com/rss", since_hours=24 * 365, ignore=ig)
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# _enrich_epss
# ─────────────────────────────────────────────────────────────────────────────


class TestEnrichEpss:
    """_enrich_epss sets card['epss_score'] from FIRST.org data with caching."""

    def test_placeholder_mode_skips_enrichment(self):
        cards = [{"title": "CVE-2026-1234 bug", "summary": ""}]
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            cache_path = f.name
        try:
            # placeholder_mode() returns True by default in CI (conftest sets env var)
            _enrich_epss(cards, cache_path)
            assert "epss_score" not in cards[0]
        finally:
            os.unlink(cache_path)

    def test_cache_hit_sets_epss_score(self):
        cards = [{"title": "CVE-2026-9999 RCE", "summary": ""}]
        now_iso = datetime.now(timezone.utc).isoformat()
        cache_data = {"CVE-2026-9999": {"epss": 0.75, "percentile": 0.95, "cached_at": now_iso}}
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(cache_data, f)
            cache_path = f.name
        try:
            with patch("agent.ingest.placeholder_mode", return_value=False):
                _enrich_epss(cards, cache_path)
            assert cards[0]["epss_score"] == pytest.approx(0.75)
        finally:
            os.unlink(cache_path)

    def test_no_cves_sets_epss_none(self):
        cards = [{"title": "generic advisory no cve", "summary": ""}]
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            cache_path = f.name
        try:
            with patch("agent.ingest.placeholder_mode", return_value=False):
                _enrich_epss(cards, cache_path)
            assert cards[0]["epss_score"] is None
        finally:
            os.unlink(cache_path)

    def test_api_fetch_populates_score(self):
        cards = [{"title": "CVE-2026-7777 exploit", "summary": ""}]
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            cache_path = f.name
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [{"cve": "CVE-2026-7777", "epss": "0.55", "percentile": "0.90"}]
        }
        try:
            with patch("agent.ingest.placeholder_mode", return_value=False), \
                 patch("agent.ingest.requests.get", return_value=mock_resp):
                _enrich_epss(cards, cache_path)
            assert cards[0]["epss_score"] == pytest.approx(0.55)
        finally:
            os.unlink(cache_path)

    def test_stale_cache_triggers_refetch(self):
        cards = [{"title": "CVE-2026-5555 vuln", "summary": ""}]
        stale_iso = "2000-01-01T00:00:00+00:00"
        cache_data = {"CVE-2026-5555": {"epss": 0.1, "percentile": 0.2, "cached_at": stale_iso}}
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(cache_data, f)
            cache_path = f.name
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [{"cve": "CVE-2026-5555", "epss": "0.88", "percentile": "0.99"}]
        }
        try:
            with patch("agent.ingest.placeholder_mode", return_value=False), \
                 patch("agent.ingest.requests.get", return_value=mock_resp):
                _enrich_epss(cards, cache_path)
            assert cards[0]["epss_score"] == pytest.approx(0.88)
        finally:
            os.unlink(cache_path)
