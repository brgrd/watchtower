# Watchtower Pipeline Eval — 2026-07-23T21:16:47Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 496 |
| After dedup + CVE merge | 494 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/496 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,133 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6746

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 67% |
| CVE coverage | 67% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 2 | 67% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 304 |
| `bsi_germany` | 138 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 8 |
| `cisa_alerts` | 7 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-22 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 6 | 1 |
| 2026-07-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |