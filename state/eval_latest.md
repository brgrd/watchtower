# Watchtower Pipeline Eval — 2026-07-01T10:06:53Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 701 |
| After dedup + CVE merge | 701 |
| Sent to Groq | 1 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/701 (0.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,701 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7928

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 120 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 50% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 1 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 128 |
| `msrc_update_guide` | 54 |
| `thehackernews` | 5 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-29 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-30 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 0% | 3 | 0 |