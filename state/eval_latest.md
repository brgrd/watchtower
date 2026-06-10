# Watchtower Pipeline Eval — 2026-06-10T22:15:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 183 |
| After dedup + CVE merge | 179 |
| Sent to Groq | 22 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/183 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,370 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6409

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 36 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 25% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 125 |
| `bsi_germany` | 15 |
| `bleepingcomputer` | 8 |
| `msrc_update_guide` | 8 |
| `securityweek` | 7 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-09 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-09 | 15 | ? | 0% | 0% | 6 | 0 |
| 2026-06-09 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-06-10 | 2 | 2 | 100% | 0% | 0 | 0 |