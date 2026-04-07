# Watchtower Pipeline Eval — 2026-04-07T22:52:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 547 |
| After dedup + CVE merge | 544 |
| Sent to Groq | 30 |
| Groq findings returned | 5 |
| Passed quality gate | 5 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/547 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,153 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8063

## Card Quality

**5 cards** — P1: 2, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 58 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 40% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 57.2 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **5** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 5 | 100% |
| NVD (CVE) | 2 | 40% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 323 |
| `bsi_germany` | 161 |
| `securityweek` | 10 |
| `bleepingcomputer` | 9 |
| `darkreading` | 9 |
| _(+19 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-03 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 1 | 1 | 100% | 0% | 0 | 0 |
| 2026-04-05 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-05 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-06 | 3 | 2 | 67% | 0% | 3 | 0 |