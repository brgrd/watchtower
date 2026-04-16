# Watchtower Pipeline Eval — 2026-04-16T22:55:55Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 248 |
| After dedup + CVE merge | 248 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/248 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,461 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8340

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 82 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 33% specific, 67% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 128 |
| `nvd` | 72 |
| `bleepingcomputer` | 9 |
| `securityweek` | 9 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-14 | 3 | 3 | 100% | 100% | 0 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-15 | 3 | 2 | 100% | 0% | 1 | 0 |
| 2026-04-15 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-04-15 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-16 | 3 | 3 | 100% | 0% | 3 | 0 |