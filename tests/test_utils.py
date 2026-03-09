"""
Tests for pure utility functions in agent.runner.

All tests are marked `unit` — no network I/O, no filesystem writes,
no external services.
"""

import pytest
from datetime import date

from agent.runner import (
    _compact_text,
    _contains_any,
    _extract_cves,
    _is_exploitish,
    _derive_priority,
    _purge_seen_ttl,
    add_ignore,
    deduplicate,
    is_ignored,
    is_private_host,
    item_hash,
    now_utc_iso,
    sha256,
)

pytestmark = pytest.mark.unit


# ── sha256 ────────────────────────────────────────────────────────────────────


class TestSha256:
    def test_deterministic(self):
        assert sha256("hello") == sha256("hello")

    def test_different_inputs_differ(self):
        assert sha256("a") != sha256("b")

    def test_returns_64_hex_chars(self):
        assert len(sha256("anything")) == 64
        assert all(c in "0123456789abcdef" for c in sha256("x"))

    def test_empty_string(self):
        # Must not raise; empty-string hash is well-defined
        assert len(sha256("")) == 64


# ── now_utc_iso ───────────────────────────────────────────────────────────────


class TestNowUtcIso:
    def test_returns_iso_format(self):
        result = now_utc_iso()
        assert "T" in result

    def test_timezone_aware(self):
        # datetime.now(timezone.utc).isoformat() always includes +00:00
        result = now_utc_iso()
        assert result.endswith("+00:00"), f"Expected +00:00 suffix, got: {result}"

    def test_freezegun_controlled(self):
        from freezegun import freeze_time

        with freeze_time("2026-03-05 12:30:00"):
            result = now_utc_iso()
        assert result.startswith("2026-03-05T12:30:00")


# ── is_private_host ───────────────────────────────────────────────────────────


class TestIsPrivateHost:
    @pytest.mark.parametrize(
        "url",
        [
            "https://10.0.0.1/api",
            "https://192.168.1.100/admin",
            "https://172.16.0.1/secret",
            "https://127.0.0.1/local",
            "https://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
            "https://myserver.local/share",
            "https://fileserver.lan/files",
            "https://[::1]/ipv6",
        ],
    )
    def test_private_urls_blocked(self, url):
        assert is_private_host(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
            "https://www.bleepingcomputer.com/news/security/",
            "https://api.groq.com/openai/v1/chat/completions",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    )
    def test_public_urls_allowed(self, url):
        assert is_private_host(url) is False


# ── add_ignore / is_ignored ───────────────────────────────────────────────────


class TestIgnoreRegistry:
    def test_empty_registry_allows_everything(self, empty_ignore):
        assert is_ignored(empty_ignore, "https://example.com/page") is False

    def test_ignored_domain_blocks_any_path(self, empty_ignore):
        add_ignore(empty_ignore, "domain", "example.com", ttl_days=7)
        assert is_ignored(empty_ignore, "https://example.com/any/path") is True
        assert is_ignored(empty_ignore, "https://example.com/") is True

    def test_ignored_exact_url(self, empty_ignore):
        add_ignore(empty_ignore, "url", "https://example.com/bad-page", ttl_days=7)
        assert is_ignored(empty_ignore, "https://example.com/bad-page") is True
        assert is_ignored(empty_ignore, "https://example.com/other") is False

    def test_ignored_url_prefix(self, empty_ignore):
        empty_ignore["ignore_url_prefix"] = {"https://spam.example.com/": "2099-01-01"}
        assert is_ignored(empty_ignore, "https://spam.example.com/article/1") is True
        assert is_ignored(empty_ignore, "https://legit.example.com/article") is False

    def test_non_matching_domain_still_allowed(self, empty_ignore):
        add_ignore(empty_ignore, "domain", "evil.com", ttl_days=7)
        assert is_ignored(empty_ignore, "https://good.com/page") is False

    def test_add_ignore_stores_valid_iso_date(self, empty_ignore):
        add_ignore(empty_ignore, "domain", "example.com", ttl_days=30)
        ttl_str = empty_ignore["ignore_domain"]["example.com"]
        # Must be a parseable ISO date; will raise ValueError if not
        date.fromisoformat(ttl_str)

    def test_add_ignore_idempotent_overwrite(self, empty_ignore):
        add_ignore(empty_ignore, "domain", "example.com", ttl_days=7)
        add_ignore(empty_ignore, "domain", "example.com", ttl_days=30)
        ttl = empty_ignore["ignore_domain"]["example.com"]
        # Both are valid dates; second write should have overwritten
        date.fromisoformat(ttl)


# ── item_hash / deduplicate / _purge_seen_ttl ─────────────────────────────────


class TestDeduplication:
    def test_item_hash_is_deterministic(self, sample_item):
        assert item_hash(sample_item) == item_hash(sample_item)

    def test_different_urls_produce_different_hashes(self, sample_item):
        other = {**sample_item, "url": "https://example.com/different"}
        assert item_hash(sample_item) != item_hash(other)

    def test_deduplicate_passes_new_items(self, sample_item):
        fresh, seen = deduplicate([sample_item], set())
        assert len(fresh) == 1
        assert item_hash(sample_item) in seen

    def test_deduplicate_drops_already_seen(self, sample_item):
        _, seen = deduplicate([sample_item], set())
        fresh2, _ = deduplicate([sample_item], seen)
        assert len(fresh2) == 0

    def test_deduplicate_preserves_insertion_order(self, sample_item):
        items = [
            {**sample_item, "url": f"https://example.com/{i}", "title": f"item {i}"}
            for i in range(5)
        ]
        fresh, _ = deduplicate(items, set())
        assert [it["title"] for it in fresh] == [f"item {i}" for i in range(5)]

    def test_purge_seen_caps_oversized_set(self):
        # _purge_seen_ttl reads CONFIG budgets.seen_ttl_days (=14) rather than
        # the passed ttl_days argument, giving max_size = 14 * 2000 = 28 000.
        huge = {str(i) for i in range(100_000)}
        purged = _purge_seen_ttl(huge, ttl_days=14)
        assert len(purged) <= 28_000

    def test_purge_seen_does_not_shrink_small_set(self):
        small = {"a", "b", "c"}
        assert _purge_seen_ttl(small, ttl_days=7) == small


# ── text helpers ──────────────────────────────────────────────────────────────


class TestCompactText:
    def test_collapses_internal_whitespace(self):
        assert _compact_text("hello   world") == "hello world"

    def test_strips_leading_trailing_whitespace(self):
        assert _compact_text("  foo  ") == "foo"

    def test_handles_newlines_and_tabs(self):
        assert _compact_text("\n\tfoo\nbar\t") == "foo bar"

    def test_empty_string_returns_empty(self):
        assert _compact_text("") == ""

    def test_none_returns_empty(self):
        assert _compact_text(None) == ""


class TestExtractCves:
    def test_single_cve(self):
        assert _extract_cves("CVE-2026-1001 is critical") == ["CVE-2026-1001"]

    def test_multiple_cves_sorted(self):
        result = _extract_cves("CVE-2024-9999 and CVE-2024-1234 both affected")
        assert result == ["CVE-2024-1234", "CVE-2024-9999"]

    def test_case_insensitive_input(self):
        assert _extract_cves("cve-2026-9999 is bad") == ["CVE-2026-9999"]

    def test_deduplicates(self):
        assert _extract_cves("CVE-2026-1001 and CVE-2026-1001 again") == [
            "CVE-2026-1001"
        ]

    def test_no_cves_returns_empty_list(self):
        assert _extract_cves("no vulnerabilities here") == []

    def test_empty_string(self):
        assert _extract_cves("") == []


class TestContainsAny:
    def test_match_first_term(self):
        assert _contains_any("exploit detected", ("exploit", "poc")) is True

    def test_match_second_term(self):
        assert _contains_any("poc published", ("exploit", "poc")) is True

    def test_case_insensitive(self):
        assert _contains_any("EXPLOIT in PROD", ("exploit",)) is True

    def test_no_match(self):
        assert _contains_any("routine maintenance", ("exploit", "zero-day")) is False

    def test_empty_terms_never_matches(self):
        assert _contains_any("anything goes here", ()) is False

    def test_empty_text(self):
        assert _contains_any("", ("exploit",)) is False


# ── _is_exploitish ────────────────────────────────────────────────────────────


class TestIsExploitish:
    @pytest.mark.parametrize(
        "title, summary",
        [
            ("exploit found", ""),
            ("", "actively exploited in production"),
            ("zero-day disclosed by researcher", ""),
            ("", "known exploited vulnerability added to KEV"),
            ("threat actors spotted in the wild", ""),
        ],
    )
    def test_positive_signals(self, title, summary):
        assert _is_exploitish({"title": title, "summary": summary}) is True

    def test_no_signals_returns_false(self):
        assert (
            _is_exploitish(
                {"title": "Routine patch released", "summary": "Minor bugfix."}
            )
            is False
        )

    def test_empty_card_returns_false(self):
        assert _is_exploitish({}) is False

    def test_signal_in_summary_only(self):
        assert (
            _is_exploitish(
                {"title": "Security update", "summary": "exploit code published"}
            )
            is True
        )


# ── _derive_priority ──────────────────────────────────────────────────────────


class TestDerivePriority:
    @pytest.mark.parametrize("label", ["P1", "P2", "P3"])
    def test_explicit_priority_passes_through(self, label):
        assert _derive_priority({"priority": label, "risk_score": 10}) == label

    def test_explicit_priority_case_insensitive(self):
        assert _derive_priority({"priority": "p1", "risk_score": 0}) == "P1"

    def test_high_score_infers_p1(self):
        assert _derive_priority({"risk_score": 90}) == "P1"
        assert _derive_priority({"risk_score": 85}) == "P1"

    def test_medium_score_infers_p2(self):
        assert _derive_priority({"risk_score": 75}) == "P2"
        assert _derive_priority({"risk_score": 60}) == "P2"

    def test_low_score_infers_p3(self):
        assert _derive_priority({"risk_score": 59}) == "P3"
        assert _derive_priority({"risk_score": 0}) == "P3"

    def test_missing_priority_and_score_defaults_to_p3(self):
        assert _derive_priority({}) == "P3"

    def test_explicit_priority_overrides_high_score(self):
        # P3 explicitly set, even with risk_score=99
        assert _derive_priority({"priority": "P3", "risk_score": 99}) == "P3"
