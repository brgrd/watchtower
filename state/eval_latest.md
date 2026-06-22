# Watchtower Pipeline Eval — 2026-06-22T21:10:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 81 |
| After dedup + CVE merge | 77 |
| Sent to Groq | 30 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/81 (18.5%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 57.3 / 65 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **11** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2.4 | Mean shelf_days: 23.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `gcp_security` | 30 |
| `bsi_germany` | 23 |
| `thehackernews` | 8 |
| `securityweek` | 6 |
| `bleepingcomputer` | 5 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-20 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-21 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-21 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-21 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-21 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-22 | 3 | 3 | 100% | 0% | 3 | 0 |