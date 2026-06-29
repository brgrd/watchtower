# Watchtower Pipeline Eval — 2026-06-29T22:16:10Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 268 |
| After dedup + CVE merge | 263 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/268 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,008 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6933

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 75.5 chars (50% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 0% generic

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
| `nvd` | 183 |
| `bsi_germany` | 43 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 7 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-27 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-06-28 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-28 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-29 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-29 | 3 | 1 | 100% | 33% | 3 | 0 |