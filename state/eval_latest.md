# Watchtower Pipeline Eval — 2026-07-21T22:09:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 461 |
| After dedup + CVE merge | 452 |
| Sent to Groq | 28 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/461 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 16,804 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 5990

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 34 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 40% specific, 60% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 283 |
| `bsi_germany` | 120 |
| `cisa_alerts` | 11 |
| `thehackernews` | 9 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-19 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | ? | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | ? | 100% | 0% | 1 | 0 |
| 2026-07-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | 1 | 100% | 33% | 3 | 0 |