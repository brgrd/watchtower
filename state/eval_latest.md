# Watchtower Pipeline Eval — 2026-06-09T21:56:33Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 861 |
| After dedup + CVE merge | 651 |
| Sent to Groq | 17 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/861 (1.7%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 59.3 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **6** | Evolving (2–5): **9** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 14.1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 7% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `msrc_update_guide` | 261 |
| `gcp_security` | 30 |
| `bsi_germany` | 24 |
| `bleepingcomputer` | 10 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 1 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-09 | 2 | 2 | 100% | 100% | 2 | 0 |