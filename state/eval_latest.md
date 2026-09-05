# Watchtower Pipeline Eval — 2026-09-05T21:07:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 68 |
| After dedup + CVE merge | 66 |
| Sent to Groq | 66 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/68 (22.1%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 52.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **14** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 1.1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 13% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 59 |
| `thehackernews` | 4 |
| `bleepingcomputer` | 2 |
| `darkreading` | 2 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-03 | 5 | ? | 0% | 0% | 4 | 0 |
| 2026-09-03 | 9 | ? | 0% | 0% | 8 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-04 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-04 | 11 | ? | 0% | 0% | 10 | 0 |
| 2026-09-04 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-05 | 1 | ? | 0% | 0% | 0 | 0 |