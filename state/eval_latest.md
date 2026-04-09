# Watchtower Pipeline Eval — 2026-04-09T22:55:00Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 499 |
| After dedup + CVE merge | 497 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/499 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,997 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8423

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 97.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 357 |
| `bsi_germany` | 85 |
| `bleepingcomputer` | 12 |
| `securityweek` | 10 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-04 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 1 | 1 | 100% | 0% | 0 | 0 |
| 2026-04-05 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-05 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-06 | 3 | 2 | 67% | 0% | 3 | 0 |
| 2026-04-07 | 5 | 2 | 100% | 40% | 5 | 0 |
| 2026-04-08 | 3 | 1 | 100% | 0% | 3 | 0 |