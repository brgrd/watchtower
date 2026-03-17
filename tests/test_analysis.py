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
    _quality_score,
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
    """Base finding passes the quality gate: title > 20, summary > 60, why_now set."""

    def _f(self, **overrides) -> dict:
        base = {
            "title": "Remote code execution vulnerability in kernel",
            "risk_score": 60,
            "domains": ["os_kernel"],
            "summary": "A critical security vulnerability allows unauthenticated remote code execution via crafted packets.",
            "why_now": "Actively exploited in the wild this week.",
        }
        base.update(overrides)
        return base

    def test_empty_findings_returns_empty_list(self):
        assert _findings_to_cards([]) == []

    def test_non_dict_finding_skipped(self):
        findings = ["not-a-dict", None, 42]
        assert _findings_to_cards(findings) == []

    def test_risk_score_clamped_to_100(self):
        cards = _findings_to_cards([self._f(risk_score=150)])
        assert cards[0]["risk_score"] == 100

    def test_risk_score_clamped_to_zero(self):
        cards = _findings_to_cards([self._f(risk_score=-50)])
        assert cards[0]["risk_score"] == 0

    def test_invalid_risk_score_defaults_to_40(self):
        cards = _findings_to_cards([self._f(risk_score="bad")])
        assert cards[0]["risk_score"] == 40

    def test_unknown_domain_falls_to_uncategorised(self):
        cards = _findings_to_cards([self._f(domains=["nonexistent_domain"])])
        assert cards[0]["domains"] == ["uncategorised"]

    def test_empty_domains_falls_to_uncategorised(self):
        cards = _findings_to_cards([self._f(domains=[])])
        assert cards[0]["domains"] == ["uncategorised"]

    def test_valid_domain_preserved(self):
        cards = _findings_to_cards([self._f(domains=["container"])])
        assert "container" in cards[0]["domains"]

    def test_refs_not_list_normalised(self):
        cards = _findings_to_cards([self._f(references="not-a-list")])
        assert cards[0]["sources"]["primary"] == []

    def test_summary_includes_why_now(self):
        cards = _findings_to_cards([self._f(summary="Base summary text here.", why_now="Active exploitation.")])
        assert "Active exploitation." in cards[0]["summary"]

    def test_summary_includes_priority_prefix(self):
        cards = _findings_to_cards([self._f(priority="P1")])
        assert cards[0]["summary"].startswith("[P1]")

    def test_confidence_formatted_in_summary(self):
        cards = _findings_to_cards([self._f(confidence=0.85)])
        assert "0.85" in cards[0]["summary"]

    def test_patch_status_patched_when_patch_available(self):
        url = "https://nvd.nist.gov/vuln/detail/CVE-2026-1111"
        finding = self._f(
            title="CVE-2026-1111 kernel privilege escalation",
            risk_score=70,
            references=[{"title": "NVD", "url": url}],
        )
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
        finding = self._f(
            title="CVE-2026-2222 remote code execution exploit",
            risk_score=80,
            references=[{"title": "NVD", "url": url}],
        )
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
            self._f(title="Low severity kernel information disclosure", risk_score=30),
            self._f(title="High severity kernel remote code execution", risk_score=90),
            self._f(title="Medium severity kernel privilege escalation", risk_score=60),
        ]
        cards = _findings_to_cards(findings)
        scores = [c["risk_score"] for c in cards]
        assert scores == sorted(scores, reverse=True)

    def test_tactic_name_normalized(self):
        cards = _findings_to_cards([self._f(tactic_name="privesc")])
        assert cards[0]["tactic_name"] == "Privilege Escalation"

    def test_unrecognized_tactic_name_cleared(self):
        cards = _findings_to_cards([self._f(tactic_name="totally_made_up_garbage")])
        assert cards[0]["tactic_name"] == ""

    def test_title_truncated_to_140_chars(self):
        cards = _findings_to_cards([self._f(title="A" * 200)])
        assert len(cards[0]["title"]) == 140

    def test_is_kev_false_when_no_all_items(self):
        cards = _findings_to_cards([self._f(title="CVE-2026-1234 remote code execution in kernel")])
        assert cards[0]["is_kev"] is False

    def test_is_kev_true_when_cve_in_kev_source(self):
        f = self._f(title="CVE-2026-9999 remote code execution in runtime", risk_score=75)
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
        f = self._f(title="CVE-2026-1111 kernel vulnerability exploitation", risk_score=60)
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
        f = self._f(title="CVE-2026-5555 privilege escalation in kernel", risk_score=50)
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
        cards = _findings_to_cards([self._f(title="No CVE mentioned — general threat advisory")])
        assert cards[0]["corroboration_count"] == 1

    def test_corroboration_count_single_source(self):
        f = self._f(title="CVE-2026-7777 kernel network stack overflow", risk_score=50, domains=["network"])
        item = {"title": "CVE-2026-7777 patch", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-7777", "summary": ""}
        cards = _findings_to_cards([f], all_items=[item])
        assert cards[0]["corroboration_count"] == 1

    def test_corroboration_count_multiple_sources(self):
        f = self._f(title="CVE-2026-8888 remote code execution advisory", risk_score=70, domains=["network"])
        items = [
            {"title": "CVE-2026-8888 advisory", "url": "https://example.com/1", "summary": ""},
            {"title": "CVE-2026-8888 patch", "url": "https://example.com/2", "summary": ""},
            {"title": "CVE-2026-8888 cisa", "url": "https://example.com/3", "source_id": "cisa_kev", "summary": ""},
        ]
        cards = _findings_to_cards([f], all_items=items)
        assert cards[0]["corroboration_count"] == 3

    def test_corroboration_count_max_across_cves(self):
        # Finding has two CVEs; one appears in 3 sources, other in 1 — should pick max
        f = self._f(title="CVE-2026-1001 and CVE-2026-1002 combined kernel flaw", risk_score=60, domains=["network"])
        items = [
            {"title": "CVE-2026-1001 source A", "url": "https://example.com/a1", "summary": ""},
            {"title": "CVE-2026-1001 source B", "url": "https://example.com/a2", "summary": ""},
            {"title": "CVE-2026-1001 source C", "url": "https://example.com/a3", "summary": ""},
            {"title": "CVE-2026-1002 source X", "url": "https://example.com/b1", "summary": ""},
        ]
        cards = _findings_to_cards([f], all_items=items)
        assert cards[0]["corroboration_count"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# _quality_score
# ─────────────────────────────────────────────────────────────────────────────


class TestQualityScore:
    """_quality_score awards 0–4 points; cards must score ≥ 2 to pass the gate."""

    def _card(self, title="", summary="", why_now="", enrichment=None):
        return {
            "title": title,
            "summary": summary,
            "why_now": why_now,
            "enrichment": enrichment or {},
        }

    def test_all_four_criteria_met_scores_4(self):
        card = self._card(
            title="Remote code execution in container runtime",
            summary="A critical vulnerability allows unauthenticated RCE via crafted requests to the runtime API.",
            why_now="Actively exploited in the wild since yesterday.",
            enrichment={"cves": ["CVE-2026-1234"], "products": ["containerd"]},
        )
        assert _quality_score(card) == 4

    def test_short_title_costs_one_point(self):
        card = self._card(
            title="Bug",  # ≤ 20 chars → no point
            summary="A critical vulnerability allows unauthenticated RCE via crafted requests.",
            why_now="Exploited in the wild.",
            enrichment={"cves": ["CVE-2026-1234"]},
        )
        assert _quality_score(card) == 3

    def test_no_cve_or_product_costs_one_point(self):
        card = self._card(
            title="Remote code execution in container runtime",
            summary="A critical vulnerability allows unauthenticated RCE via crafted requests.",
            why_now="Exploited in the wild.",
            enrichment={},  # no cves, no products
        )
        assert _quality_score(card) == 3

    def test_short_summary_costs_one_point(self):
        card = self._card(
            title="Remote code execution in container runtime",
            summary="Short.",  # ≤ 60 chars
            why_now="Exploited in the wild.",
            enrichment={"cves": ["CVE-2026-1234"]},
        )
        assert _quality_score(card) == 3

    def test_missing_why_now_costs_one_point(self):
        card = self._card(
            title="Remote code execution in container runtime",
            summary="A critical vulnerability allows unauthenticated RCE via crafted requests.",
            why_now="",
            enrichment={"cves": ["CVE-2026-1234"]},
        )
        assert _quality_score(card) == 3

    def test_zero_score_for_empty_card(self):
        assert _quality_score({}) == 0

    def test_score_1_for_title_only(self):
        card = self._card(title="Remote code execution in runtime")
        assert _quality_score(card) == 1

    def test_products_alone_satisfies_cve_criterion(self):
        card = self._card(
            title="Remote code execution in container runtime",
            summary="A critical vulnerability allows unauthenticated RCE via crafted requests.",
            why_now="Exploited.",
            enrichment={"products": ["nginx"]},  # no CVE but has product
        )
        assert _quality_score(card) == 4

    @pytest.mark.parametrize(
        "title,summary,why_now,enrichment,expected_pass",
        [
            # Score 4 — passes
            ("Remote code execution in runtime", "A " * 35, "Exploited now.", {"cves": ["CVE-2026-1"]}, True),
            # Score 2 — passes (title + summary)
            ("Remote code execution in runtime", "A " * 35, "", {}, True),
            # Score 1 — filtered (title only)
            ("Remote code execution in runtime", "Short.", "", {}, False),
            # Score 0 — filtered
            ("Bad", "Short.", "", {}, False),
        ],
    )
    def test_gate_threshold_parametrized(self, title, summary, why_now, enrichment, expected_pass):
        card = self._card(title=title, summary=summary, why_now=why_now, enrichment=enrichment)
        assert (_quality_score(card) >= 2) == expected_pass


class TestFindingsToCardsQualityGate:
    """_findings_to_cards must drop low-quality cards via _quality_score < 2."""

    def _good_finding(self, title="Remote code execution in container runtime"):
        return {
            "title": title,
            "risk_score": 70,
            "priority": "P2",
            "summary": "A critical vulnerability allows unauthenticated RCE via crafted API requests to the runtime.",
            "why_now": "Actively exploited in the wild since this week.",
            "domains": ["container"],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234", "title": "NVD CVE-2026-1234"}],
        }

    def _noise_finding(self):
        return {
            "title": "Up",  # short title — 0 pts
            "risk_score": 30,
            "priority": "P3",
            "summary": "Some activity.",  # short — 0 pts
            "why_now": "",  # no why_now — 0 pts
            "domains": [],
            "references": [],
        }

    def test_good_finding_survives_gate(self):
        cards = _findings_to_cards([self._good_finding()])
        assert len(cards) == 1

    def test_noise_finding_filtered_by_gate(self):
        cards = _findings_to_cards([self._noise_finding()])
        assert len(cards) == 0

    def test_mixed_findings_only_good_survives(self):
        cards = _findings_to_cards([self._good_finding(), self._noise_finding()])
        assert len(cards) == 1
        assert "Remote code execution" in cards[0]["title"]


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
