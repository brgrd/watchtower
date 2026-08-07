# Watchtower Pipeline Eval — 2026-08-07T11:01:42Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 194 |
| After dedup + CVE merge | 194 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/194 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,594 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7717

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 78.5 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 25% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 92 |
| `nvd` | 91 |
| `thehackernews` | 6 |
| `securityweek` | 5 |
| `bleepingcomputer` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-05 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-05 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-08-05 | 3 | ? | 67% | 100% | 3 | 0 |
| 2026-08-06 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-08-06 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |