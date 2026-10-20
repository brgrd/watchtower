# Watchtower Pipeline Eval — 2026-10-20T23:46:52Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 698 |
| After dedup + CVE merge | 687 |
| Sent to Groq | 7 |
| Groq findings returned | 0 |
| Final cards rendered | 7 |
| **Pipeline yield** | **7/698 (1.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**7 cards** — P1: 0, P2: 0, P3: 7

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65.7 / 85 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 7 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **6** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.4 | Mean shelf_days: 20.4

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 14% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 126 |
| `thehackernews` | 10 |
| `bleepingcomputer` | 9 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-20 | 15 | ? | 0% | 0% | 1 | 0 |
| 2026-10-20 | 1 | ? | 0% | 0% | 1 | 0 |