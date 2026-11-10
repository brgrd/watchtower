# Watchtower Pipeline Eval — 2026-11-10T22:17:26Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 2045 |
| After dedup + CVE merge | 2032 |
| Sent to Groq | 11 |
| Groq findings returned | 0 |
| Final cards rendered | 11 |
| **Pipeline yield** | **11/2045 (0.5%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**11 cards** — P1: 0, P2: 0, P3: 11

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56.4 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 11 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **9** | Evolving (2–5): **1** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 4.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 1182 |
| `nvd` | 500 |
| `bsi_germany` | 250 |
| `gcp_security` | 30 |
| `thehackernews` | 17 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-04 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-11-05 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-11-06 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-11-06 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-11-08 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-11-08 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-10 | 5 | ? | 0% | 0% | 3 | 0 |