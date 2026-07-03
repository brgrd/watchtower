# Watchtower Pipeline Eval — 2026-07-03T21:18:09Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 538 |
| After dedup + CVE merge | 497 |
| Sent to Groq | 1 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/538 (0.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,715 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7922

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 119 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 100% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 33

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 100% |
| NVD (CVE) | 1 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 328 |
| `nvd` | 128 |
| `bsi_germany` | 70 |
| `thehackernews` | 5 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 33% | 2 | 0 |
| 2026-07-02 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-07-03 | 3 | 3 | 100% | 0% | 3 | 0 |