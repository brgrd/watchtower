# Watchtower Pipeline Eval — 2026-05-08T19:46:47Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 499 |
| After dedup + CVE merge | 496 |
| Sent to Groq | 1 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/499 (0.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,754 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8414

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 115 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 1 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 291 |
| `bsi_germany` | 141 |
| `msrc_update_guide` | 33 |
| `bleepingcomputer` | 6 |
| `thehackernews` | 6 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-04 | 3 | 1 | 67% | 0% | 3 | 0 |
| 2026-05-05 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-06 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-07 | 3 | 2 | 100% | 67% | 2 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 1 | 1 | 100% | 100% | 1 | 0 |