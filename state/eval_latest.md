# Watchtower Pipeline Eval — 2026-07-14T22:07:37Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 1254 |
| After dedup + CVE merge | 890 |
| Sent to Groq | 6 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/1254 (0.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,383 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6715

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 95 / 90 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 50.5 chars (50% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 573 |
| `nvd` | 500 |
| `bsi_germany` | 120 |
| `bleepingcomputer` | 13 |
| `thehackernews` | 9 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-13 | 3 | ? | 100% | 0% | 2 | 0 |
| 2026-07-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-07-14 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-14 | 3 | 3 | 100% | 0% | 3 | 0 |