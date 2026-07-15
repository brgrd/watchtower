# Watchtower Pipeline Eval — 2026-07-15T21:10:21Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 352 |
| After dedup + CVE merge | 332 |
| Sent to Groq | 25 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/352 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,329 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6808

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 46.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 7.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 221 |
| `bsi_germany` | 83 |
| `securityweek` | 9 |
| `thehackernews` | 8 |
| `bleepingcomputer` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-14 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-14 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-07-14 | 3 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-15 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 0% | 2 | 0 |