"""Developer-facing evaluation and reporting for the Watchtower pipeline.

Collected each run and written to:
  state/eval_latest.md   — human-readable Markdown report (always overwritten)
  state/eval_log.jsonl   — rolling 30-run structured log (machine-readable)
  $GITHUB_STEP_SUMMARY   — GitHub Actions job summary tab (when env var is set)

Not rendered into the public briefing HTML.
"""

import json
import os
import re
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Reasoning quality heuristics ─────────────────────────────────────────────

# Actions containing these patterns are considered "specific" (good signal)
_SPECIFIC_RE = re.compile(
    r"CVE-\d{4}-\d+"          # CVE ID
    r"|port\s+\d+"             # port number
    r"|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # IP address
    r"|\bpatch\b|\bupdate\b|\bupgrade\b"
    r"|\bblock\b|\bisolate\b|\bdisable\b"
    r"|\brotate\b|\brevoke\b|\bsegment\b"
    r"|\bfirewall\b|\bMFA\b|\b2FA\b",
    re.I,
)

# Actions containing these phrases are generic noise (bad signal)
_GENERIC_PHRASES = (
    "monitor for",
    "stay informed",
    "follow best practices",
    "review security",
    "consult vendor",
    "be aware",
    "keep an eye",
    "remain vigilant",
)

_EVAL_LOG_MAX_RUNS = 30


# ── EvalCollector ─────────────────────────────────────────────────────────────

class EvalCollector:
    """Accumulates metrics throughout a single pipeline run."""

    def __init__(self):
        self.ts = datetime.now(timezone.utc).isoformat()
        self._pipeline: dict[str, int] = {}
        self._groq: dict = {}
        self._cards: list = []
        self._enrichment: dict = {}
        self._feed_yields: dict[str, int] = {}

    # ── Recording API ─────────────────────────────────────────────────────────

    def record_stage(self, stage: str, count: int) -> None:
        """Record item count at a named pipeline stage."""
        self._pipeline[stage] = count

    def record_groq(self, meta: dict) -> None:
        """Record Groq call metadata (from analysis._last_groq_meta)."""
        self._groq = dict(meta)

    def record_feed_yields(self, feed_run_metrics: dict) -> None:
        """Record per-feed item counts from the feed_run_metrics dict."""
        self._feed_yields = {
            fid: m.get("count", 0)
            for fid, m in feed_run_metrics.items()
        }

    def record_enrichment(
        self, *, epss_hits: int, nvd_hits: int, kev_hits: int, total: int
    ) -> None:
        self._enrichment = {
            "epss_hits": epss_hits,
            "nvd_hits": nvd_hits,
            "kev_hits": kev_hits,
            "total": total,
        }

    def set_cards(self, cards: list) -> None:
        """Set the final cards list for quality analysis."""
        self._cards = list(cards)

    # ── Internal analysis ─────────────────────────────────────────────────────

    def _analyze_cards(self) -> dict:
        cards = self._cards
        if not cards:
            return {}

        n = len(cards)
        priority_dist = dict(Counter(c.get("priority", "P3") for c in cards))
        risk_scores = [c.get("risk_score", 0) for c in cards]

        # Tactic coverage
        tactic_valid = sum(1 for c in cards if c.get("tactic_name"))

        # Patch status distribution
        patch_dist = dict(Counter(c.get("patch_status", "unknown") for c in cards))

        # CVE coverage
        cve_present = sum(
            1 for c in cards if (c.get("enrichment") or {}).get("cves")
        )

        # why_now quality
        why_now_lens = [len(c.get("why_now") or "") for c in cards]

        # Recommended action specificity
        action_total = 0
        action_specific = 0
        action_generic = 0
        for c in cards:
            for a in c.get("recommended_actions_24h") or []:
                action_total += 1
                if _SPECIFIC_RE.search(a):
                    action_specific += 1
                elif any(g in a.lower() for g in _GENERIC_PHRASES):
                    action_generic += 1

        # Persistence distribution
        run_counts = [c.get("run_count", 1) for c in cards]
        shelf_days_vals = [c.get("shelf_days", 0) for c in cards]
        resolved_count = sum(1 for c in cards if c.get("shelf_resolved"))

        sorted_risk = sorted(risk_scores)
        p90_idx = max(0, int(n * 0.9) - 1)

        return {
            "count": n,
            "priority_dist": priority_dist,
            "risk_scores": {
                "mean": round(statistics.mean(risk_scores), 1) if risk_scores else 0,
                "p90": sorted_risk[p90_idx] if sorted_risk else 0,
                "min": min(risk_scores, default=0),
                "max": max(risk_scores, default=0),
            },
            "tactic_coverage_pct": round(tactic_valid / n * 100),
            "patch_status_dist": patch_dist,
            "cve_coverage_pct": round(cve_present / n * 100),
            "why_now": {
                "mean_chars": round(statistics.mean(why_now_lens), 1) if why_now_lens else 0,
                "pct_substantive": round(
                    sum(1 for ln in why_now_lens if ln > 60) / n * 100
                ),
            },
            "actions": {
                "total": action_total,
                "pct_specific": round(action_specific / action_total * 100) if action_total else 0,
                "pct_generic": round(action_generic / action_total * 100) if action_total else 0,
            },
            "persistence": {
                "new_count": sum(1 for r in run_counts if r == 1),
                "evolving_count": sum(1 for r in run_counts if 2 <= r <= 5),
                "persistent_count": sum(1 for r in run_counts if r > 5),
                "resolved_count": resolved_count,
                "mean_run_count": round(statistics.mean(run_counts), 1) if run_counts else 0,
                "mean_shelf_days": round(statistics.mean(shelf_days_vals), 1) if shelf_days_vals else 0,
            },
        }

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "pipeline": self._pipeline,
            "groq": self._groq,
            "cards": self._analyze_cards(),
            "enrichment": self._enrichment,
            "feed_yields": self._feed_yields,
        }

    # ── Rendering ─────────────────────────────────────────────────────────────

    def render_markdown(self, prior_runs: Optional[list] = None) -> str:
        d = self.to_dict()
        pipe = d["pipeline"]
        groq = d["groq"]
        cards = d["cards"]
        enrich = d["enrichment"]

        lines: list[str] = [
            f"# Watchtower Pipeline Eval — {self.ts[:19]}Z",
            "",
            "## Pipeline Yield",
            "",
            "| Stage | Count |",
            "|-------|------:|",
        ]
        stage_labels = {
            "polled_raw": "Items polled (raw)",
            "after_dedup_cve_merge": "After dedup + CVE merge",
            "groq_input": "Sent to Groq",
            "groq_findings": "Groq findings returned",
            "post_quality_gate": "Passed quality gate",
            "final_cards": "Final cards rendered",
        }
        for stage, count in pipe.items():
            label = stage_labels.get(stage, stage)
            lines.append(f"| {label} | {count} |")

        # Yield ratio
        raw = pipe.get("polled_raw", 0)
        final = pipe.get("final_cards", 0)
        if raw:
            ratio = round(final / raw * 100, 1)
            lines.append(f"| **Pipeline yield** | **{final}/{raw} ({ratio}%)** |")

        # Groq call
        lines += ["", "## Groq"]
        if groq:
            model = groq.get("model", "unknown")
            payload_chars = groq.get("payload_chars", "?")
            parse_ok = groq.get("parse_ok", True)
            retries = groq.get("retries", 0)
            rpd_rem = groq.get("rpd_rem", "?")
            tpm_rem = groq.get("tpm_rem", "?")
            parse_icon = "✓" if parse_ok else "✗"

            lines += [
                f"- **Model**: `{model}`",
                f"- **Payload**: {payload_chars:,} chars" if isinstance(payload_chars, int) else f"- **Payload**: {payload_chars} chars",
                f"- **Parse**: {parse_icon}  |  **Retries**: {retries}",
                f"- **Rate limit remaining** — requests: {rpd_rem}, tokens: {tpm_rem}",
            ]
        else:
            lines.append("_Groq not called this run (placeholder mode or no API key)._")

        # Card quality
        if cards:
            pd = cards["priority_dist"]
            rs = cards["risk_scores"]
            wn = cards["why_now"]
            ac = cards["actions"]
            ps = cards["persistence"]
            patch = cards["patch_status_dist"]

            lines += [
                "",
                "## Card Quality",
                "",
                f"**{cards['count']} cards** — "
                f"P1: {pd.get('P1', 0)}, P2: {pd.get('P2', 0)}, P3: {pd.get('P3', 0)}",
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Risk score mean / p90 | {rs['mean']} / {rs['p90']} |",
                f"| Tactic coverage | {cards['tactic_coverage_pct']}% |",
                f"| CVE coverage | {cards['cve_coverage_pct']}% |",
                f"| Patch status | " + "  ".join(f"{k}: {v}" for k, v in sorted(patch.items())) + " |",
                "",
                "### Reasoning Quality",
                "",
                f"- **`why_now` avg length**: {wn['mean_chars']} chars "
                f"({wn['pct_substantive']}% ≥ 60 chars, considered substantive)",
                f"- **Recommended actions**: {ac['total']} total — "
                f"{ac['pct_specific']}% specific, {ac['pct_generic']}% generic",
                "",
                "### Persistence",
                "",
                f"- New (run=1): **{ps['new_count']}** | "
                f"Evolving (2–5): **{ps['evolving_count']}** | "
                f"Persistent (>5): **{ps['persistent_count']}** | "
                f"Resolved: **{ps['resolved_count']}**",
                f"- Mean run_count: {ps['mean_run_count']} | Mean shelf_days: {ps['mean_shelf_days']}",
            ]

        # Enrichment
        if enrich and enrich.get("total", 0) > 0:
            total = enrich["total"]
            lines += [
                "",
                "## Enrichment Hit Rates",
                "",
                f"| Source | Hits | Rate |",
                f"|--------|-----:|-----:|",
                f"| EPSS | {enrich.get('epss_hits', 0)} | {round(enrich.get('epss_hits', 0) / total * 100)}% |",
                f"| NVD (CVE) | {enrich.get('nvd_hits', 0)} | {round(enrich.get('nvd_hits', 0) / total * 100)}% |",
                f"| CISA KEV | {enrich.get('kev_hits', 0)} | {round(enrich.get('kev_hits', 0) / total * 100)}% |",
            ]

        # Feed yield
        if d["feed_yields"]:
            sorted_feeds = sorted(
                d["feed_yields"].items(), key=lambda x: x[1], reverse=True
            )
            lines += [
                "",
                "## Feed Yield",
                "",
                "| Feed | Items |",
                "|------|------:|",
            ]
            top = sorted_feeds[:5]
            bottom = [f for f in sorted_feeds[5:] if f[1] == 0]
            for fid, cnt in top:
                lines.append(f"| `{fid}` | {cnt} |")
            if len(sorted_feeds) > 5:
                lines.append(f"| _(+{len(sorted_feeds) - 5} more)_ | … |")
            if bottom:
                lines += ["", f"**{len(bottom)} feeds returned 0 items this run.**"]

        # Cross-run trend
        if prior_runs and len(prior_runs) >= 2:
            trend_runs = prior_runs[-7:]
            lines += [
                "",
                "## 7-Run Trend",
                "",
                "| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |",
                "|------|---------|----|---------|------|-----|------------|",
            ]
            for r in trend_runs:
                rc = r.get("cards", {})
                run_date = r.get("ts", "")[:10]
                pd_r = rc.get("priority_dist", {})
                ps_r = rc.get("persistence", {})
                lines.append(
                    f"| {run_date} "
                    f"| {rc.get('count', '?')} "
                    f"| {pd_r.get('P1', '?')} "
                    f"| {rc.get('tactic_coverage_pct', '?')}% "
                    f"| {rc.get('cve_coverage_pct', '?')}% "
                    f"| {ps_r.get('new_count', '?')} "
                    f"| {ps_r.get('persistent_count', '?')} |"
                )

        return "\n".join(lines)

    # ── Output ────────────────────────────────────────────────────────────────

    def _append_eval_log(self, log_path: str) -> None:
        """Append this run's record and prune to last 30 entries."""
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(self.to_dict(), ensure_ascii=False) + "\n")

        lines = Path(log_path).read_text(encoding="utf-8").splitlines()
        if len(lines) > _EVAL_LOG_MAX_RUNS:
            Path(log_path).write_text(
                "\n".join(lines[-_EVAL_LOG_MAX_RUNS:]) + "\n", encoding="utf-8"
            )

    def _load_prior_runs(self, log_path: str) -> list:
        if not os.path.exists(log_path):
            return []
        runs = []
        for line in Path(log_path).read_text(encoding="utf-8").splitlines():
            try:
                runs.append(json.loads(line))
            except Exception:
                pass
        return runs

    def write_report(self, state_dir: str) -> str:
        """Write eval_latest.md, append to eval_log.jsonl, push to GHA summary.

        Returns the path to eval_latest.md.
        """
        os.makedirs(state_dir, exist_ok=True)
        log_path = os.path.join(state_dir, "eval_log.jsonl")
        md_path = os.path.join(state_dir, "eval_latest.md")

        prior_runs = self._load_prior_runs(log_path)
        md = self.render_markdown(prior_runs)

        Path(md_path).write_text(md, encoding="utf-8")
        self._append_eval_log(log_path)

        gha_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if gha_summary:
            with open(gha_summary, "a", encoding="utf-8") as f:
                f.write(md + "\n")

        return md_path
