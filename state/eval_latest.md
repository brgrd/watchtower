# Watchtower Pipeline Eval — 2026-07-07T12:06:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 269 |
| After dedup + CVE merge | 268 |
| Sent to Groq | 30 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/269 (5.6%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **10** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 3.1 | Mean shelf_days: 33.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 144 |
| `nvd` | 67 |
| `gcp_security` | 30 |
| `msrc_update_guide` | 15 |
| `bleepingcomputer` | 4 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-04 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-05 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-07-07 | 2 | 1 | 100% | 0% | 2 | 0 |