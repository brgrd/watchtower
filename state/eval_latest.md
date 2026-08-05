# Watchtower Pipeline Eval — 2026-08-05T21:20:43Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 350 |
| After dedup + CVE merge | 348 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/350 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,313 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6517

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 62 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 251 |
| `bsi_germany` | 51 |
| `thehackernews` | 11 |
| `securityweek` | 8 |
| `bleepingcomputer` | 5 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-03 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-08-04 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-04 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-04 | 3 | 1 | 100% | 67% | 3 | 0 |
| 2026-08-04 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-05 | 2 | 2 | 100% | 100% | 0 | 0 |
| 2026-08-05 | 3 | 2 | 100% | 0% | 3 | 0 |