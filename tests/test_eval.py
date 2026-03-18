"""Tests for agent.eval.EvalCollector — developer-facing pipeline eval."""

import json
import os

import pytest

from agent.eval import EvalCollector

pytestmark = pytest.mark.unit


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _sample_cards() -> list[dict]:
    return [
        {
            "id": "c1",
            "title": "CVE-2026-1234 in OpenSSL",
            "risk_score": 88,
            "priority": "P1",
            "tactic_name": "Initial Access",
            "patch_status": "no_fix",
            "why_now": "Actively exploited in the wild with public PoC; no patch available from vendor.",
            "recommended_actions_24h": [
                "Patch OpenSSL to version 3.2.1 immediately",
                "Block inbound port 443 on affected hosts",
            ],
            "run_count": 1,
            "shelf_days": 0,
            "shelf_resolved": False,
            "is_kev": True,
            "epss_score": 0.87,
            "enrichment": {"cves": ["CVE-2026-1234"], "products": ["openssl"]},
            "domains": ["os_kernel"],
            "sources": {"primary": [], "secondary": []},
        },
        {
            "id": "c2",
            "title": "Browser supply-chain compromise",
            "risk_score": 64,
            "priority": "P2",
            "tactic_name": "Execution",
            "patch_status": "workaround",
            "why_now": "Malicious update path used.",
            "recommended_actions_24h": ["Monitor for suspicious extension updates"],
            "run_count": 6,
            "shelf_days": 8,
            "shelf_resolved": False,
            "is_kev": False,
            "epss_score": None,
            "enrichment": {"cves": [], "products": []},
            "domains": ["browser_ext"],
            "sources": {"primary": [], "secondary": []},
        },
        {
            "id": "c3",
            "title": "Resolved finding",
            "risk_score": 50,
            "priority": "P3",
            "tactic_name": "",
            "patch_status": "patched",
            "why_now": "",
            "recommended_actions_24h": [],
            "run_count": 3,
            "shelf_days": 5,
            "shelf_resolved": True,
            "is_kev": False,
            "epss_score": None,
            "enrichment": {"cves": [], "products": []},
            "domains": [],
            "sources": {"primary": [], "secondary": []},
        },
    ]


def _collector_with_cards() -> EvalCollector:
    ec = EvalCollector()
    ec.record_stage("polled_raw", 80)
    ec.record_stage("after_dedup_cve_merge", 45)
    ec.record_stage("groq_input", 40)
    ec.record_stage("groq_findings", 8)
    ec.record_stage("post_quality_gate", 6)
    ec.record_stage("final_cards", 3)
    ec.record_groq({
        "model": "llama-3.3-70b-versatile",
        "payload_chars": 8500,
        "parse_ok": True,
        "retries": 0,
        "rpd_rem": "98",
        "tpm_rem": "15000",
    })
    ec.record_feed_yields({"cisa_kev": {"count": 5}, "nvd": {"count": 10}, "feed_a": {"count": 3}})
    ec.record_enrichment(epss_hits=1, nvd_hits=1, kev_hits=1, total=3)
    ec.set_cards(_sample_cards())
    return ec


# ── Pipeline stage recording ──────────────────────────────────────────────────

class TestPipelineStages:
    def test_stages_stored(self):
        ec = EvalCollector()
        ec.record_stage("polled_raw", 50)
        ec.record_stage("final_cards", 5)
        d = ec.to_dict()
        assert d["pipeline"]["polled_raw"] == 50
        assert d["pipeline"]["final_cards"] == 5

    def test_empty_stages(self):
        ec = EvalCollector()
        assert ec.to_dict()["pipeline"] == {}


# ── Groq metadata recording ───────────────────────────────────────────────────

class TestGroqRecording:
    def test_groq_meta_stored(self):
        ec = EvalCollector()
        ec.record_groq({"model": "llama-3.3-70b-versatile", "parse_ok": True, "retries": 2})
        d = ec.to_dict()
        assert d["groq"]["model"] == "llama-3.3-70b-versatile"
        assert d["groq"]["retries"] == 2

    def test_empty_groq_when_not_recorded(self):
        ec = EvalCollector()
        assert ec.to_dict()["groq"] == {}


# ── Feed yield recording ──────────────────────────────────────────────────────

class TestFeedYields:
    def test_yields_extracted_from_feed_run_metrics(self):
        ec = EvalCollector()
        ec.record_feed_yields({
            "cisa_kev": {"count": 5, "ok": True},
            "feed_b": {"count": 0, "ok": False},
        })
        d = ec.to_dict()
        assert d["feed_yields"]["cisa_kev"] == 5
        assert d["feed_yields"]["feed_b"] == 0


# ── Card quality analysis ─────────────────────────────────────────────────────

class TestCardAnalysis:
    def test_priority_distribution(self):
        ec = EvalCollector()
        ec.set_cards(_sample_cards())
        cards = ec.to_dict()["cards"]
        assert cards["priority_dist"] == {"P1": 1, "P2": 1, "P3": 1}

    def test_tactic_coverage_excludes_empty(self):
        ec = EvalCollector()
        ec.set_cards(_sample_cards())
        cards = ec.to_dict()["cards"]
        # c3 has empty tactic_name → 2/3 = 66%
        assert cards["tactic_coverage_pct"] == 67

    def test_cve_coverage_only_counts_cards_with_cves(self):
        ec = EvalCollector()
        ec.set_cards(_sample_cards())
        cards = ec.to_dict()["cards"]
        # Only c1 has CVEs
        assert cards["cve_coverage_pct"] == 33

    def test_patch_status_distribution(self):
        ec = EvalCollector()
        ec.set_cards(_sample_cards())
        patch = ec.to_dict()["cards"]["patch_status_dist"]
        assert patch == {"no_fix": 1, "workaround": 1, "patched": 1}

    def test_persistence_counts(self):
        ec = EvalCollector()
        ec.set_cards(_sample_cards())
        ps = ec.to_dict()["cards"]["persistence"]
        assert ps["new_count"] == 1      # c1: run_count=1
        assert ps["evolving_count"] == 1  # c3: run_count=3
        assert ps["persistent_count"] == 1  # c2: run_count=6
        assert ps["resolved_count"] == 1  # c3: shelf_resolved=True

    def test_empty_cards_returns_empty_dict(self):
        ec = EvalCollector()
        assert ec.to_dict()["cards"] == {}


# ── Reasoning quality heuristics ─────────────────────────────────────────────

class TestReasoningQuality:
    def test_specific_action_detected(self):
        ec = EvalCollector()
        ec.set_cards([{
            "id": "x", "title": "T", "risk_score": 80, "priority": "P1",
            "tactic_name": "Execution", "patch_status": "unknown",
            "why_now": "A" * 70,
            "recommended_actions_24h": ["Patch OpenSSL to 3.2.1 immediately"],
            "run_count": 1, "shelf_days": 0, "shelf_resolved": False,
            "is_kev": False, "epss_score": None,
            "enrichment": {"cves": [], "products": []},
            "domains": [], "sources": {"primary": [], "secondary": []},
        }])
        actions = ec.to_dict()["cards"]["actions"]
        assert actions["pct_specific"] == 100
        assert actions["pct_generic"] == 0

    def test_generic_action_detected(self):
        ec = EvalCollector()
        ec.set_cards([{
            "id": "x", "title": "T", "risk_score": 50, "priority": "P2",
            "tactic_name": "Persistence", "patch_status": "unknown",
            "why_now": "Short",
            "recommended_actions_24h": ["Monitor for suspicious activity"],
            "run_count": 1, "shelf_days": 0, "shelf_resolved": False,
            "is_kev": False, "epss_score": None,
            "enrichment": {"cves": [], "products": []},
            "domains": [], "sources": {"primary": [], "secondary": []},
        }])
        actions = ec.to_dict()["cards"]["actions"]
        assert actions["pct_generic"] == 100

    def test_why_now_substantive_threshold(self):
        ec = EvalCollector()
        long_why = "A" * 65
        short_why = "Short."
        ec.set_cards([
            {
                "id": "a", "title": "T", "risk_score": 80, "priority": "P1",
                "tactic_name": "Impact", "patch_status": "no_fix",
                "why_now": long_why, "recommended_actions_24h": [],
                "run_count": 1, "shelf_days": 0, "shelf_resolved": False,
                "is_kev": False, "epss_score": None,
                "enrichment": {"cves": [], "products": []},
                "domains": [], "sources": {"primary": [], "secondary": []},
            },
            {
                "id": "b", "title": "T2", "risk_score": 40, "priority": "P3",
                "tactic_name": "Discovery", "patch_status": "unknown",
                "why_now": short_why, "recommended_actions_24h": [],
                "run_count": 1, "shelf_days": 0, "shelf_resolved": False,
                "is_kev": False, "epss_score": None,
                "enrichment": {"cves": [], "products": []},
                "domains": [], "sources": {"primary": [], "secondary": []},
            },
        ])
        wn = ec.to_dict()["cards"]["why_now"]
        assert wn["pct_substantive"] == 50


# ── Enrichment hit rates ──────────────────────────────────────────────────────

class TestEnrichmentRates:
    def test_rates_stored_and_retrievable(self):
        ec = EvalCollector()
        ec.record_enrichment(epss_hits=3, nvd_hits=2, kev_hits=1, total=5)
        d = ec.to_dict()["enrichment"]
        assert d["epss_hits"] == 3
        assert d["kev_hits"] == 1
        assert d["total"] == 5


# ── Markdown rendering ────────────────────────────────────────────────────────

class TestMarkdownRendering:
    def test_pipeline_section_present(self):
        md = _collector_with_cards().render_markdown()
        assert "## Pipeline Yield" in md
        assert "polled_raw" not in md  # stage keys are replaced by labels
        assert "Items polled (raw)" in md
        assert "80" in md

    def test_yield_ratio_shown(self):
        md = _collector_with_cards().render_markdown()
        assert "Pipeline yield" in md
        assert "3/80" in md

    def test_groq_section_present(self):
        md = _collector_with_cards().render_markdown()
        assert "## Groq" in md
        assert "llama-3.3-70b-versatile" in md
        assert "8,500 chars" in md

    def test_groq_not_called_message(self):
        ec = EvalCollector()
        md = ec.render_markdown()
        assert "not called" in md.lower() or "placeholder" in md.lower()

    def test_card_quality_section_present(self):
        md = _collector_with_cards().render_markdown()
        assert "## Card Quality" in md
        assert "P1: 1" in md
        assert "Reasoning Quality" in md

    def test_enrichment_section_present(self):
        md = _collector_with_cards().render_markdown()
        assert "## Enrichment Hit Rates" in md
        assert "EPSS" in md

    def test_feed_yield_section_present(self):
        md = _collector_with_cards().render_markdown()
        assert "## Feed Yield" in md
        assert "cisa_kev" in md

    def test_trend_table_requires_two_prior_runs(self):
        ec = EvalCollector()
        # Single prior run — no trend table
        md = ec.render_markdown(prior_runs=[{"ts": "2026-03-17T06:00:00", "cards": {}}])
        assert "7-Run Trend" not in md

    def test_trend_table_shown_with_two_runs(self):
        prior = [
            {"ts": "2026-03-17T06:00:00", "cards": {"count": 8, "priority_dist": {"P1": 2},
             "tactic_coverage_pct": 75, "cve_coverage_pct": 50,
             "persistence": {"new_count": 3, "persistent_count": 1}}},
            {"ts": "2026-03-18T06:00:00", "cards": {"count": 6, "priority_dist": {"P1": 1},
             "tactic_coverage_pct": 83, "cve_coverage_pct": 66,
             "persistence": {"new_count": 2, "persistent_count": 2}}},
        ]
        ec = EvalCollector()
        md = ec.render_markdown(prior_runs=prior)
        assert "7-Run Trend" in md
        assert "2026-03-17" in md


# ── File output ───────────────────────────────────────────────────────────────

class TestFileOutput:
    def test_write_report_creates_md_and_jsonl(self, tmp_path):
        ec = _collector_with_cards()
        md_path = ec.write_report(str(tmp_path))
        assert os.path.exists(md_path)
        log_path = tmp_path / "eval_log.jsonl"
        assert log_path.exists()
        lines = log_path.read_text().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert "pipeline" in record
        assert "cards" in record

    def test_eval_log_appends_across_runs(self, tmp_path):
        for _ in range(3):
            ec = _collector_with_cards()
            ec.write_report(str(tmp_path))
        log_path = tmp_path / "eval_log.jsonl"
        lines = log_path.read_text().splitlines()
        assert len(lines) == 3

    def test_eval_log_pruned_at_30(self, tmp_path):
        # Pre-populate with 29 entries
        log_path = tmp_path / "eval_log.jsonl"
        fake = json.dumps({"ts": "2026-01-01T00:00:00", "pipeline": {}, "groq": {},
                           "cards": {}, "enrichment": {}, "feed_yields": {}})
        log_path.write_text("\n".join([fake] * 29) + "\n")
        # Write two more (total would be 31)
        ec = _collector_with_cards()
        ec.write_report(str(tmp_path))
        ec.write_report(str(tmp_path))
        lines = log_path.read_text().splitlines()
        assert len(lines) == 30

    def test_github_summary_written_when_env_set(self, tmp_path, monkeypatch):
        summary_path = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
        ec = _collector_with_cards()
        ec.write_report(str(tmp_path))
        assert summary_path.exists()
        content = summary_path.read_text()
        assert "Watchtower Pipeline Eval" in content

    def test_github_summary_not_written_without_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        summary_path = tmp_path / "summary.md"
        ec = _collector_with_cards()
        ec.write_report(str(tmp_path))
        assert not summary_path.exists()
