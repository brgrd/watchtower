# Watchtower Pipeline Eval — 2026-03-31T22:47:19Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 457 |
| After dedup + CVE merge | 456 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/457 (0.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,471 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8312

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 50.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 272 |
| `bsi_germany` | 130 |
| `bleepingcomputer` | 10 |
| `securityweek` | 10 |
| `darkreading` | 7 |
| _(+19 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-28 | 3 | 1 | 100% | 100% | 2 | 0 |
| 2026-03-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-03-29 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-29 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-03-30 | 3 | 1 | 100% | 0% | 2 | 0 |