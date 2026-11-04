# Watchtower Pipeline Eval — 2026-11-04T01:13:05Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 851 |
| After dedup + CVE merge | 845 |
| Sent to Groq | 11 |
| Groq findings returned | 0 |
| Final cards rendered | 11 |
| **Pipeline yield** | **11/851 (1.3%)** |

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

- New (run=1): **8** | Evolving (2–5): **2** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 1.9 | Mean shelf_days: 12.4

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 250 |
| `gcp_security` | 31 |
| `thehackernews` | 14 |
| `bleepingcomputer` | 10 |
| _(+21 more)_ | … |

**7 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-30 | 6 | ? | 0% | 0% | 3 | 0 |
| 2026-10-30 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-10-31 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-10-31 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-11-01 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-01 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-02 | 6 | ? | 0% | 0% | 4 | 0 |