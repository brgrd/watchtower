# Watchtower Pipeline Eval — 2026-11-25T12:35:40Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 903 |
| After dedup + CVE merge | 887 |
| Sent to Groq | 17 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/903 (1.7%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 55.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **14** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 0.8

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 4 | 27% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 250 |
| `gcp_security` | 30 |
| `thehackernews` | 25 |
| `bleepingcomputer` | 15 |
| _(+21 more)_ | … |

**6 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-19 | 6 | ? | 0% | 0% | 3 | 1 |
| 2026-11-20 | 8 | ? | 0% | 0% | 8 | 0 |
| 2026-11-21 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-11-21 | 4 | ? | 0% | 0% | 1 | 1 |
| 2026-11-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-23 | 3 | ? | 0% | 0% | 3 | 0 |