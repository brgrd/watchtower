# Watchtower Pipeline Eval — 2026-07-08T12:47:27Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 199 |
| After dedup + CVE merge | 197 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/199 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,821 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7384

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 55 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 99 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 0% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 99 |
| `nvd` | 81 |
| `thehackernews` | 6 |
| `bleepingcomputer` | 5 |
| `securityweek` | 3 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-06 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-07-07 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-07 | 15 | ? | 0% | 0% | 4 | 1 |
| 2026-07-07 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 100% | 3 | 0 |