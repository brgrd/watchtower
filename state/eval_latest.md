# Watchtower Pipeline Eval — 2026-07-15T23:07:19Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 338 |
| After dedup + CVE merge | 318 |
| Sent to Groq | 25 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/338 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,439 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6961

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 31.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 67% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 263 |
| `bsi_germany` | 34 |
| `darkreading` | 6 |
| `bleepingcomputer` | 5 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-14 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-07-14 | 3 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-15 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 50% | 1 | 0 |