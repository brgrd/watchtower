# Watchtower Pipeline Eval — 2026-05-11T22:15:41Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 375 |
| After dedup + CVE merge | 374 |
| Sent to Groq | 28 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/375 (4.0%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 62.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **14** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 0.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 7 | 47% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 285 |
| `gcp_security` | 30 |
| `bsi_germany` | 29 |
| `bleepingcomputer` | 6 |
| `securityweek` | 6 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-09 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-11 | 2 | 1 | 100% | 50% | 2 | 0 |