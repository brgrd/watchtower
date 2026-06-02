# Watchtower Pipeline Eval — 2026-06-02T00:22:11Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 316 |
| After dedup + CVE merge | 316 |
| Sent to Groq | 25 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/316 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,248 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6961

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 48.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 25% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 1.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 280 |
| `bleepingcomputer` | 8 |
| `darkreading` | 5 |
| `msrc_update_guide` | 5 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-31 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-31 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-31 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-31 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 100% | 3 | 0 |