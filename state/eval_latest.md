# Watchtower Pipeline Eval — 2026-11-13T00:08:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 680 |
| After dedup + CVE merge | 672 |
| Sent to Groq | 9 |
| Groq findings returned | 0 |
| Final cards rendered | 9 |
| **Pipeline yield** | **9/680 (1.3%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**9 cards** — P1: 0, P2: 0, P3: 9

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50.6 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 9 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **7** | Evolving (2–5): **1** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 2.1 | Mean shelf_days: 4.9

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 11% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 366 |
| `bsi_germany` | 250 |
| `thehackernews` | 16 |
| `bleepingcomputer` | 12 |
| `securityweek` | 10 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-06 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-11-08 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-11-08 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-10 | 5 | ? | 0% | 0% | 3 | 0 |
| 2026-11-10 | 11 | ? | 0% | 0% | 9 | 1 |
| 2026-11-11 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-11-12 | 3 | ? | 0% | 0% | 3 | 0 |