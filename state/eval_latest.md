# Watchtower Pipeline Eval — 2026-04-10T22:50:39Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 491 |
| After dedup + CVE merge | 491 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/491 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,207 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8384

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 67% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 303 |
| `bsi_germany` | 147 |
| `securityweek` | 9 |
| `bleepingcomputer` | 6 |
| `darkreading` | 6 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-04 | 1 | 1 | 100% | 0% | 0 | 0 |
| 2026-04-05 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-05 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-06 | 3 | 2 | 67% | 0% | 3 | 0 |
| 2026-04-07 | 5 | 2 | 100% | 40% | 5 | 0 |
| 2026-04-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-09 | 3 | 1 | 100% | 0% | 2 | 0 |