# Watchtower Pipeline Eval — 2026-07-23T10:32:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 374 |
| After dedup + CVE merge | 371 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/374 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,053 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7303

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 31 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 33% specific, 67% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 234 |
| `nvd` | 79 |
| `msrc_update_guide` | 45 |
| `bleepingcomputer` | 3 |
| `securityweek` | 3 |
| _(+21 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-21 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-21 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 6 | 1 |
| 2026-07-23 | 3 | 1 | 100% | 0% | 2 | 0 |