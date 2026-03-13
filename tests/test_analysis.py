"""
Tests for agent.analysis helpers.

Coverage targets:
  - _normalize_tactic: all canonical names, aliases, prefix matching, edge cases
  - _enrich_cards_from_sources: corpus extraction, empty sources, non-dict cards
  - _findings_to_cards: risk clamping, domain fallback, non-dict skipping,
    patch_status derivation, confidence formatting, summary assembly
  - _match_high_profile: passthrough smoke test
  - groq_analyze_briefing: placeholder-mode fast path
"""

import pytest

from agent.analysis import (
    _enrich_cards_from_sources,
    _findings_to_cards,
    _match_high_profile,
    _normalize_tactic,
    groq_analyze_briefing,
)

pytestmark = pytest.mark.unit


# ─────────────────────────────────────────────────────────────────────────────
# _normalize_tactic
# ─────────────────────────────────────────────────────────────────────────────


class TestNormalizeTactic:
    """Canonical exact matches — all 14 tactics round-trip correctly."""

    @pytest.mark.parametrize(
        "raw",
        [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command & Control",
            "Exfiltration",
            "Impact",
        ],
    )
    def test_canonical_exact_match(self, raw):
        assert _normalize_tactic(raw) == raw

    @pytest.mark.parametrize(
        "raw",
        [
            "reconnaissance",
            "INITIAL ACCESS",
            "lateral movement",
            "IMPACT",
            "command & control",
        ],
    )
    def test_canonical_case_insensitive(self, raw):
        result = _normalize_tactic(raw)
        assert result in {
            "Reconnaissance",
            "Initial Access",
            "Lateral Movement",
            "Impact",
            "Command & Control",
        }

    @pytest.mark.parametrize(
        "alias,expected",
        [
            ("c2", "Command & Control"),
            ("C2", "Command & Control"),
            ("c&c", "Command & Control"),
            ("command and control", "Command & Control"),
            ("command-and-control", "Command & Control"),
            ("privesc", "Privilege Escalation"),
            ("priv esc", "Privilege Escalation"),
            ("privilege-escalation", "Privilege Escalation"),
            ("evasion", "Defense Evasion"),
            ("def evasion", "Defense Evasion"),
            ("defense-evasion", "Defense Evasion"),
            ("recon", "Reconnaissance"),
            ("exfil", "Exfiltration"),
            ("data exfiltration", "Exfiltration"),
            ("cred access", "Credential Access"),
            ("credential-access", "Credential Access"),
            ("credentials", "Credential Access"),
            ("lateral-movement", "Lateral Movement"),
            ("exec", "Execution"),
            ("execute", "Execution"),
            ("persist", "Persistence"),
            ("collect", "Collection"),
            ("impact", "Impact"),
            ("resource dev", "Resource Development"),
            ("resource-dev", "Resource Development"),
            ("initial access", "Initial Access"),
        ],
    )
    def test_known_aliases(self, alias, expected):
        assert _normalize_tactic(alias) == expected

    @pytest.mark.parametrize(
        "prefix,expected",
        [
            ("Privilege Esc", "Privilege Escalation"),
            ("Lateral Mov", "Lateral Movement"),
            ("Reconn", "Reconnaissance"),
        ],
    )
    def test_prefix_match(self, prefix, expected):
        assert _normalize_tactic(prefix) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            None,
            "Totally Made Up Tactic",
            "ATT&CK",
            "TA0001",
        ],
    )
    def test_unrecognized_returns_empty(self, raw):
        result = _normalize_tactic(raw or "")
        assert result == ""

    def test_whitespace_stripped(self):
        assert _normalize_tactic("  Impact  ") == "Impact"


# ─────────────────────────────────────────────────────────────────────────────
# _enrich_cards_from_sources
# ─────────────────────────────────────────────────────────────────────────────


def _make_card(title="CVE-2026-1234 OpenSSL RCE", url="https://example.com/advisory"):
    return {
        "id": "testcard",
        "title": title,
        "summary": f"[P1] {title}",
        "risk_score": 75,
        "domains": ["crypto_lib"],
        "sources": {
            "primary": [{"title": "Advisory", "url": url}],
            "secondary": [],
        },
    }


def _make_item(url="https://example.com/advisory", text="", title="", pub=""):
    return {
        "url": url,
        "title": title or "Advisory Title",
        "extracted_text": text,
        "summary": text[:200] if not text else "",
        "published_at": pub,
    }


class TestEnrichCardsFromSources:
    def test_no_all_items_skips_gracefully(self):
        cards = [_make_card()]
        _enrich_cards_from_sources(cards, None)
        assert "enrichment" not in cards[0]

    def test_empty_all_items_skips_gracefully(self):
        cards = [_make_card()]
        _enrich_cards_from_sources(cards, [])
        assert "enrichment" not in cards[0]

    def test_no_matching_url_sets_source_count_zero(self):
        cards = [_make_card(url="https://example.com/advisory")]
        all_items = [_make_item(url="https://other.com/other")]
        _enrich_cards_from_sources(cards, all_items)
        assert cards[0]["enrichment"]["source_count"] == 0

    def test_cve_extraction_from_article_text(self):
        url = "https://example.com/advisory"
        cards = [_make_card(title="OpenSSL Bug", url=url)]
        all_items = [
            _make_item(
                url=url,
                text="CVE-2026-9999 and CVE-2026-8888 are both exploited. Affects OpenSSL.",
            )
        ]
        _enrich_cards_from_sources(cards, all_items)
        enr = cards[0]["enrichment"]
        assert "CVE-2026-9999" in enr["cves"]
        assert "CVE-2026-8888" in enr["cves"]
        assert enr["source_count"] == 1

    def test_extra_cves_flagged_separately(self):
        url = "https://example.com/advisory"
        # Card title mentions CVE-2026-1111, article also has CVE-2026-2222
        cards = [_make_card(title="CVE-2026-1111 OpenSSL", url=url)]
        all_items = [
            _make_item(
                url=url,
                text="CVE-2026-1111 is the primary vuln. CVE-2026-2222 also related.",
            )
        ]
        _enrich_cards_from_sources(cards, all_items)
        enr = cards[0]["enrichment"]
        assert "CVE-2026-1111" in enr["cves"]
        assert "CVE-2026-2222" in enr["extra_cves"]

    def test_product_extraction(self):
        url = "https://example.com/advisory"
        cards = [_make_card(url=url)]
        all_items = [_make_item(url=url, text="Cisco IOS XE is affected by this RCE.")]
        _enrich_cards_from_sources(cards, all_items)
        assert "Cisco IOS XE" in cards[0]["enrichment"]["products"]

    def test_version_extraction(self):
        url = "https://example.com/advisory"
        cards = [_make_card(url=url)]
        all_items = [
            _make_item(url=url, text="Affected versions include 3.11.2 and v2.5.1.")
        ]
        _enrich_cards_from_sources(cards, all_items)
        versions = cards[0]["enrichment"]["versions"]
        assert any("3.11.2" in v or "2.5.1" in v for v in versions)

    def test_date_extraction(self):
        url = "https://example.com/advisory"
        cards = [_make_card(url=url)]
        all_items = [_make_item(url=url, text="Published 2026-03-12, patched 2026-03-10.")]
        _enrich_cards_from_sources(cards, all_items)
        dates = cards[0]["enrichment"]["dates"]
        assert any("2026-03-12" in d for d in dates)

    def test_lede_extracted(self):
        url = "https://example.com/advisory"
        cards = [_make_card(url=url)]
        long_sentence = "A critical remote code execution vulnerability was found in OpenSSL affecting TLS 1.3."
        all_items = [_make_item(url=url, text=long_sentence)]
        _enrich_cards_from_sources(cards, all_items)
        assert cards[0]["enrichment"]["lede"]
        assert len(cards[0]["enrichment"]["lede"]) >= 40

    def test_published_at_from_item_metadata(self):
        url = "https://example.com/advisory"
        cards = [_make_card(url=url)]
        all_items = [_make_item(url=url, text="Some article text here for testing purposes.", pub="2026-03-11T10:00:00")]
        _enrich_cards_from_sources(cards, all_items)
        assert "2026-03-11" in cards[0]["enrichment"]["dates"]

    def test_non_dict_card_skipped(self):
        cards = ["not-a-dict", _make_card()]
        url = "https://example.com/advisory"
        all_items = [_make_item(url=url, text="Some text about OpenSSL vulnerability.")]
        # Must not raise
        _enrich_cards_from_sources(cards, all_items)
        assert "enrichment" in cards[1]

    def test_fallback_to_summary_when_no_extracted_text(self):
        url = "https://example.com/advisory"
        cards = [_make_card(url=url)]
        all_items = [{"url": url, "title": "Title", "summary": "Fortinet FortiGate flaw exploited.", "published_at": ""}]
        _enrich_cards_from_sources(cards, all_items)
        enr = cards[0]["enrichment"]
        assert enr["source_count"] == 1
        assert "Fortinet FortiGate" in enr["products"]


# ─────────────────────────────────────────────────────────────────────────────
# _findings_to_cards
# ─────────────────────────────────────────────────────────────────────────────


class TestFindingsToCards:
    def test_empty_findings_returns_empty_list(self):
        assert _findings_to_cards([]) == []

    def test_non_dict_finding_skipped(self):
        findings = ["not-a-dict", None, 42]
        assert _findings_to_cards(findings) == []

    def test_risk_score_clamped_to_100(self):
        f = {"title": "Test", "risk_score": 150, "domains": ["os_kernel"]}
        cards = _findings_to_cards([f])
        assert cards[0]["risk_score"] == 100

    def test_risk_score_clamped_to_zero(self):
        f = {"title": "Test", "risk_score": -50, "domains": ["os_kernel"]}
        cards = _findings_to_cards([f])
        assert cards[0]["risk_score"] == 0

    def test_invalid_risk_score_defaults_to_40(self):
        f = {"title": "Test", "risk_score": "bad", "domains": ["os_kernel"]}
        cards = _findings_to_cards([f])
        assert cards[0]["risk_score"] == 40

    def test_unknown_domain_falls_to_uncategorised(self):
        f = {"title": "Test", "risk_score": 50, "domains": ["nonexistent_domain"]}
        cards = _findings_to_cards([f])
        assert cards[0]["domains"] == ["uncategorised"]

    def test_empty_domains_falls_to_uncategorised(self):
        f = {"title": "Test", "risk_score": 50, "domains": []}
        cards = _findings_to_cards([f])
        assert cards[0]["domains"] == ["uncategorised"]

    def test_valid_domain_preserved(self):
        f = {"title": "Test", "risk_score": 50, "domains": ["container"]}
        cards = _findings_to_cards([f])
        assert "container" in cards[0]["domains"]

    def test_refs_not_list_normalised(self):
        f = {"title": "Test", "risk_score": 50, "domains": ["os_kernel"], "references": "not-a-list"}
        cards = _findings_to_cards([f])
        assert cards[0]["sources"]["primary"] == []

    def test_summary_includes_why_now(self):
        f = {
            "title": "Test",
            "risk_score": 50,
            "domains": ["os_kernel"],
            "summary": "Base summary.",
            "why_now": "Active exploitation.",
        }
        cards = _findings_to_cards([f])
        assert "Active exploitation." in cards[0]["summary"]

    def test_summary_includes_priority_prefix(self):
        f = {
            "title": "Test",
            "risk_score": 50,
            "domains": ["os_kernel"],
            "summary": "Base.",
            "priority": "P1",
        }
        cards = _findings_to_cards([f])
        assert cards[0]["summary"].startswith("[P1]")

    def test_confidence_formatted_in_summary(self):
        f = {
            "title": "Test",
            "risk_score": 50,
            "domains": ["os_kernel"],
            "summary": "Base.",
            "confidence": 0.85,
        }
        cards = _findings_to_cards([f])
        assert "0.85" in cards[0]["summary"]

    def test_patch_status_patched_when_patch_available(self):
        url = "https://nvd.nist.gov/vuln/detail/CVE-2026-1111"
        finding = {
            "title": "CVE-2026-1111 flaw",
            "risk_score": 70,
            "domains": ["os_kernel"],
            "references": [{"title": "NVD", "url": url}],
        }
        all_items = [
            {
                "title": "CVE-2026-1111 patch released",
                "url": url,
                "summary": "Patched.",
                "patch_available": True,
                "workaround_available": False,
                "exploited_in_wild": False,
            }
        ]
        cards = _findings_to_cards([finding], all_items=all_items)
        assert cards[0]["patch_status"] == "patched"

    def test_patch_status_no_fix_when_exploited_no_patch(self):
        url = "https://nvd.nist.gov/vuln/detail/CVE-2026-2222"
        finding = {
            "title": "CVE-2026-2222 flaw",
            "risk_score": 80,
            "domains": ["os_kernel"],
            "references": [{"title": "NVD", "url": url}],
        }
        all_items = [
            {
                "title": "CVE-2026-2222 exploited",
                "url": url,
                "summary": "Exploited.",
                "patch_available": False,
                "workaround_available": False,
                "exploited_in_wild": True,
            }
        ]
        cards = _findings_to_cards([finding], all_items=all_items)
        assert cards[0]["patch_status"] == "no_fix"

    def test_cards_sorted_by_risk_score_desc(self):
        findings = [
            {"title": "Low", "risk_score": 30, "domains": ["os_kernel"]},
            {"title": "High", "risk_score": 90, "domains": ["os_kernel"]},
            {"title": "Mid", "risk_score": 60, "domains": ["os_kernel"]},
        ]
        cards = _findings_to_cards(findings)
        scores = [c["risk_score"] for c in cards]
        assert scores == sorted(scores, reverse=True)

    def test_tactic_name_normalized(self):
        f = {
            "title": "Test",
            "risk_score": 50,
            "domains": ["os_kernel"],
            "tactic_name": "privesc",
        }
        cards = _findings_to_cards([f])
        assert cards[0]["tactic_name"] == "Privilege Escalation"

    def test_unrecognized_tactic_name_cleared(self):
        f = {
            "title": "Test",
            "risk_score": 50,
            "domains": ["os_kernel"],
            "tactic_name": "totally_made_up_garbage",
        }
        cards = _findings_to_cards([f])
        assert cards[0]["tactic_name"] == ""

    def test_title_truncated_to_140_chars(self):
        f = {"title": "A" * 200, "risk_score": 50, "domains": ["os_kernel"]}
        cards = _findings_to_cards([f])
        assert len(cards[0]["title"]) == 140

    def test_is_kev_false_when_no_all_items(self):
        f = {"title": "CVE-2026-1234 vuln", "risk_score": 60, "domains": ["os_kernel"]}
        cards = _findings_to_cards([f])
        assert cards[0]["is_kev"] is False

    def test_is_kev_true_when_cve_in_kev_source(self):
        f = {"title": "CVE-2026-9999 RCE", "risk_score": 75, "domains": ["os_kernel"]}
        kev_item = {
            "title": "CVE-2026-9999 — Remote Code Execution",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
            "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "source_id": "cisa_kev",
            "summary": "",
        }
        cards = _findings_to_cards([f], all_items=[kev_item])
        assert cards[0]["is_kev"] is True

    def test_is_kev_false_when_cve_not_in_kev(self):
        f = {"title": "CVE-2026-1111 vuln", "risk_score": 60, "domains": ["os_kernel"]}
        kev_item = {
            "title": "CVE-2026-9999 — Different CVE",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
            "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "source_id": "cisa_kev",
            "summary": "",
        }
        cards = _findings_to_cards([f], all_items=[kev_item])
        assert cards[0]["is_kev"] is False

    def test_is_kev_true_via_source_string_fallback(self):
        # source_id absent but source URL contains "known_exploited"
        f = {"title": "CVE-2026-5555 bug", "risk_score": 50, "domains": ["os_kernel"]}
        kev_item = {
            "title": "CVE-2026-5555 — Exploit",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-5555",
            "source": "https://www.cisa.gov/feeds/known_exploited_vulnerabilities.json",
            "summary": "",
        }
        cards = _findings_to_cards([f], all_items=[kev_item])
        assert cards[0]["is_kev"] is True

    # ── corroboration_count ───────────────────────────────────────────────────

    def test_corroboration_count_defaults_to_one(self):
        f = {"title": "no CVE mentioned", "risk_score": 50, "domains": ["network"]}
        cards = _findings_to_cards([f])
        assert cards[0]["corroboration_count"] == 1

    def test_corroboration_count_single_source(self):
        f = {"title": "CVE-2026-7777 bug", "risk_score": 50, "domains": ["network"]}
        item = {"title": "CVE-2026-7777 patch", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-7777", "summary": ""}
        cards = _findings_to_cards([f], all_items=[item])
        assert cards[0]["corroboration_count"] == 1

    def test_corroboration_count_multiple_sources(self):
        f = {"title": "CVE-2026-8888 RCE", "risk_score": 70, "domains": ["network"]}
        items = [
            {"title": "CVE-2026-8888 advisory", "url": "https://example.com/1", "summary": ""},
            {"title": "CVE-2026-8888 patch", "url": "https://example.com/2", "summary": ""},
            {"title": "CVE-2026-8888 cisa", "url": "https://example.com/3", "source_id": "cisa_kev", "summary": ""},
        ]
        cards = _findings_to_cards([f], all_items=items)
        assert cards[0]["corroboration_count"] == 3

    def test_corroboration_count_max_across_cves(self):
        # Finding has two CVEs; one appears in 3 sources, other in 1 — should pick max
        f = {"title": "CVE-2026-1001 and CVE-2026-1002 combined", "risk_score": 60, "domains": ["network"]}
        items = [
            {"title": "CVE-2026-1001 source A", "url": "https://example.com/a1", "summary": ""},
            {"title": "CVE-2026-1001 source B", "url": "https://example.com/a2", "summary": ""},
            {"title": "CVE-2026-1001 source C", "url": "https://example.com/a3", "summary": ""},
            {"title": "CVE-2026-1002 source X", "url": "https://example.com/b1", "summary": ""},
        ]
        cards = _findings_to_cards([f], all_items=items)
        assert cards[0]["corroboration_count"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# _match_high_profile
# ─────────────────────────────────────────────────────────────────────────────


class TestMatchHighProfile:
    def test_returns_list(self):
        result = _match_high_profile("some article text")
        assert isinstance(result, list)

    def test_no_match_returns_empty(self):
        result = _match_high_profile("completely unrelated content xyz123")
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# groq_analyze_briefing — placeholder fast path
# ─────────────────────────────────────────────────────────────────────────────


class TestGroqAnalyzeBriefing:
    def test_placeholder_mode_returns_empty(self):
        executive, findings, status = groq_analyze_briefing([], [], [])
        assert executive == ""
        assert findings == []
        assert status == "placeholder"

    def test_placeholder_returns_correct_shape(self):
        result = groq_analyze_briefing(
            [{"title": "CVE-2026-1234", "summary": "test"}], [], []
        )
        assert len(result) == 3
        assert isinstance(result[1], list)
