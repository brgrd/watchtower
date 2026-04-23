# Watchtower Pipeline Eval — 2026-04-23T22:59:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 306 |
| After dedup + CVE merge | 306 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/306 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,006 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8449

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 109.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 60% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 4.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 137 |
| `bsi_germany` | 120 |
| `bleepingcomputer` | 10 |
| `github_changelog` | 8 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-19 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-04-20 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-21 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-22 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-22 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-04-23 | 3 | 1 | 100% | 0% | 2 | 0 |