# Watchtower Pipeline Eval — 2026-05-26T21:55:05Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 570 |
| After dedup + CVE merge | 566 |
| Sent to Groq | 18 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/570 (0.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,165 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6743

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 375 |
| `bsi_germany` | 124 |
| `msrc_update_guide` | 12 |
| `bleepingcomputer` | 10 |
| `securityweek` | 10 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-21 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-21 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-05-23 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-23 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-24 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-25 | 3 | 1 | 100% | 100% | 3 | 0 |