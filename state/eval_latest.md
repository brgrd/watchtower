# Watchtower Pipeline Eval — 2026-10-09T21:35:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 763 |
| After dedup + CVE merge | 757 |
| Sent to Groq | 13 |
| Groq findings returned | 0 |
| Final cards rendered | 13 |
| **Pipeline yield** | **13/763 (1.7%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**13 cards** — P1: 0, P2: 0, P3: 13

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50.8 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 13 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **7** | Evolving (2–5): **6** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.8 | Mean shelf_days: 50.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 8 | 62% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 440 |
| `bsi_germany` | 218 |
| `msrc_update_guide` | 39 |
| `thehackernews` | 13 |
| `bleepingcomputer` | 11 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-03 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-10-04 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-10-04 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-10-06 | 3 | ? | 0% | 0% | 2 | 0 |
| 2026-10-07 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-10-07 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-10-08 | 5 | ? | 0% | 0% | 4 | 0 |