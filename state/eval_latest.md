# Watchtower Pipeline Eval — 2026-04-22T22:58:49Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 404 |
| After dedup + CVE merge | 404 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/404 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,913 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8210

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 86.7 / 90 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 81.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `nvd` | 307 |
| `bsi_germany` | 55 |
| `bleepingcomputer` | 9 |
| `securityweek` | 8 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-04-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-19 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-04-20 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-21 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-22 | 3 | ? | 100% | 0% | 3 | 0 |