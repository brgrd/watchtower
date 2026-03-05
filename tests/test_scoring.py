"""
Tests for domain classification, heatmap aggregation, clustering,
scoring, and output-colour helpers.
"""

import pytest

from agent.runner import (
    _heatmap_cell_color,
    build_domain_heatmap,
    classify_domains,
    cluster_items,
    score_cluster,
    to_cluster_card,
)

pytestmark = pytest.mark.unit


# ── classify_domains ──────────────────────────────────────────────────────────


class TestClassifyDomains:
    def test_openssl_maps_to_crypto_lib(self):
        item = {"title": "OpenSSL RCE", "summary": "TLS cipher vulnerability patched"}
        assert "crypto_lib" in classify_domains(item)

    def test_npm_package_maps_to_pkg_npm(self):
        item = {"title": "Malicious npm package typosquat", "summary": ""}
        assert "pkg_npm" in classify_domains(item)

    def test_kubernetes_maps_to_container(self):
        item = {"title": "Kubernetes RBAC bypass", "summary": "kubectl ingress exploit"}
        assert "container" in classify_domains(item)

    def test_item_can_match_multiple_domains(self):
        item = {
            "title": "OpenSSL CVE in Docker container",
            "summary": "TLS issue inside kubernetes pod",
        }
        domains = classify_domains(item)
        assert "crypto_lib" in domains
        assert "container" in domains

    def test_identity_signals(self):
        item = {
            "title": "Okta SAML SSO bypass",
            "summary": "authentication token forged",
        }
        assert "identity" in classify_domains(item)

    def test_unknown_content_falls_back_to_uncategorised(self):
        item = {"title": "random headline with no known signals", "summary": ""}
        assert classify_domains(item) == ["uncategorised"]

    def test_empty_item_returns_uncategorised(self):
        assert classify_domains({}) == ["uncategorised"]

    def test_case_insensitive_matching(self):
        item = {"title": "NPM supply chain attack", "summary": "DOCKER image tampered"}
        domains = classify_domains(item)
        assert "pkg_npm" in domains or "supply_chain" in domains
        assert "container" in domains


# ── build_domain_heatmap ──────────────────────────────────────────────────────


class TestBuildDomainHeatmap:
    def test_empty_cards_all_zeros(self):
        heatmap = build_domain_heatmap([])
        assert all(v["count"] == 0 for v in heatmap.values())
        assert all(v["max_score"] == 0 for v in heatmap.values())

    def test_count_incremented_per_domain(self):
        cards = [
            {"domains": ["crypto_lib"], "risk_score": 70},
            {"domains": ["crypto_lib"], "risk_score": 50},
        ]
        heatmap = build_domain_heatmap(cards)
        assert heatmap["crypto_lib"]["count"] == 2

    def test_max_score_tracked_correctly(self):
        cards = [
            {"domains": ["os_kernel"], "risk_score": 40},
            {"domains": ["os_kernel"], "risk_score": 95},
            {"domains": ["os_kernel"], "risk_score": 60},
        ]
        heatmap = build_domain_heatmap(cards)
        assert heatmap["os_kernel"]["max_score"] == 95

    def test_uncategorised_domain_tracked(self):
        cards = [{"domains": ["uncategorised"], "risk_score": 20}]
        heatmap = build_domain_heatmap(cards)
        assert heatmap["uncategorised"]["count"] == 1

    def test_card_spanning_multiple_domains(self):
        cards = [{"domains": ["crypto_lib", "container"], "risk_score": 80}]
        heatmap = build_domain_heatmap(cards)
        assert heatmap["crypto_lib"]["count"] == 1
        assert heatmap["container"]["count"] == 1

    def test_unknown_domain_key_ignored_gracefully(self):
        cards = [{"domains": ["this_does_not_exist"], "risk_score": 50}]
        heatmap = build_domain_heatmap(cards)
        assert "this_does_not_exist" not in heatmap

    def test_heatmap_has_label_for_every_key(self):
        heatmap = build_domain_heatmap([])
        assert all("label" in v for v in heatmap.values())


# ── cluster_items ─────────────────────────────────────────────────────────────


class TestClusterItems:
    def test_cve_items_cluster_together(self):
        items = [
            {
                "title": "CVE-2026-1001 RCE",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
                "summary": "",
            },
            {
                "title": "Patch for CVE-2026-1001 released",
                "url": "https://openssl.org/news/CVE-2026-1001",
                "summary": "",
            },
        ]
        clusters = cluster_items(items)
        cve_keys = [k for k in clusters if "CVE:CVE-2026-1001" in k]
        assert len(cve_keys) == 1
        assert len(clusters[cve_keys[0]]) == 2

    def test_different_cves_produce_different_clusters(self):
        items = [
            {
                "title": "CVE-2026-1001 RCE",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
                "summary": "",
            },
            {
                "title": "CVE-2026-2002 SQLi",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-2002",
                "summary": "",
            },
        ]
        clusters = cluster_items(items)
        cve_keys = [k for k in clusters if "CLUSTER:CVE:" in k]
        assert len(cve_keys) == 2

    def test_non_cve_item_uses_domain_key(self):
        items = [
            {
                "title": "Blog post about security",
                "url": "https://krebs.example.com/story",
                "summary": "",
            }
        ]
        clusters = cluster_items(items)
        assert not any("CVE:" in k for k in clusters)
        # tldextract.registered_domain strips subdomains: krebs.example.com → example.com
        assert any("example.com" in k for k in clusters)

    def test_empty_items_returns_empty_dict(self):
        assert cluster_items([]) == {}


# ── score_cluster ─────────────────────────────────────────────────────────────


class TestScoreCluster:
    def test_cve_key_adds_base_score(self):
        score = score_cluster(
            "CLUSTER:CVE:CVE-2026-1001", [{"title": "", "summary": ""}]
        )
        assert score >= 40

    def test_exploit_signal_adds_bonus(self):
        plain = score_cluster(
            "CLUSTER:CVE:CVE-2026-1001", [{"title": "patch", "summary": ""}]
        )
        exploit = score_cluster(
            "CLUSTER:CVE:CVE-2026-1001",
            [{"title": "exploit in the wild", "summary": ""}],
        )
        assert exploit > plain

    def test_score_capped_at_100(self):
        items = [
            {
                "title": "exploit poc supply chain kubernetes openssl in the wild",
                "summary": "",
            }
        ]
        assert score_cluster("CLUSTER:CVE:CVE-2026-1001", items) <= 100

    def test_score_minimum_zero(self):
        assert score_cluster("CLUSTER:BLOG:abc123", [{"title": "", "summary": ""}]) >= 0

    def test_non_cve_cluster_has_lower_base(self):
        cve_score = score_cluster(
            "CLUSTER:CVE:CVE-2026-1001", [{"title": "", "summary": ""}]
        )
        blog_score = score_cluster("CLUSTER:BLOG:xyz", [{"title": "", "summary": ""}])
        assert cve_score > blog_score


# ── to_cluster_card ───────────────────────────────────────────────────────────


class TestToClusterCard:
    def test_card_structure(self, sample_item):
        card = to_cluster_card("CLUSTER:CVE:CVE-2026-9999", [sample_item])
        assert "id" in card
        assert "risk_score" in card
        assert "domains" in card
        assert "sources" in card
        assert isinstance(card["sources"]["primary"], list)

    def test_title_taken_from_first_item(self, sample_item):
        card = to_cluster_card("CLUSTER:CVE:CVE-2026-9999", [sample_item])
        assert card["title"] == sample_item["title"][:140]

    def test_domains_aggregated_from_items(self, sample_item):
        card = to_cluster_card("CLUSTER:CVE:CVE-2026-9999", [sample_item])
        # sample_item has "openssl" + "TLS" → should map to crypto_lib
        assert isinstance(card["domains"], list)
        assert len(card["domains"]) > 0

    def test_primary_sources_capped_at_five(self, sample_item):
        items = [
            {**sample_item, "url": f"https://example.com/{i}", "title": f"item {i}"}
            for i in range(10)
        ]
        card = to_cluster_card("CLUSTER:BLOG:x", items)
        assert len(card["sources"]["primary"]) <= 5

    def test_countries_aggregated_from_items(self, sample_item):
        card = to_cluster_card("CLUSTER:CVE:CVE-2026-9999", [sample_item])
        assert "US" in card["countries"]


# ── _heatmap_cell_color ───────────────────────────────────────────────────────


class TestHeatmapCellColor:
    def test_zero_count_neutral_grey(self):
        bg, fg = _heatmap_cell_color(0, 0)
        assert bg == "#ebedf0"

    def test_low_score_green(self):
        bg, fg = _heatmap_cell_color(20, 1)
        assert bg == "#c6e48b"

    def test_medium_score_yellow(self):
        bg, fg = _heatmap_cell_color(50, 3)
        assert bg == "#f9c74f"

    def test_elevated_score_orange(self):
        bg, fg = _heatmap_cell_color(75, 2)
        assert bg == "#f77f00"

    def test_critical_score_red(self):
        bg, fg = _heatmap_cell_color(90, 5)
        assert bg == "#d62828"

    def test_boundary_score_79_is_orange(self):
        bg, _ = _heatmap_cell_color(79, 1)
        assert bg == "#f77f00"

    def test_boundary_score_80_is_red(self):
        bg, _ = _heatmap_cell_color(80, 1)
        assert bg == "#d62828"

    def test_returns_tuple_of_two_strings(self):
        result = _heatmap_cell_color(50, 2)
        assert isinstance(result, tuple) and len(result) == 2
        assert all(isinstance(s, str) for s in result)
