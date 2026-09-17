# Watchtower Pipeline Eval — 2026-09-17T00:24:49Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 455 |
| After dedup + CVE merge | 451 |
| Sent to Groq | 1 |
| Groq findings returned | 0 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/455 (0.2%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**1 cards** — P1: 0, P2: 0, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 417 |
| `bleepingcomputer` | 5 |
| `thehackernews` | 5 |
| `securityweek` | 5 |
| `therecord` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-13 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-14 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-14 | 3 | ? | 0% | 0% | 2 | 0 |
| 2026-09-15 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-16 | 5 | ? | 0% | 0% | 5 | 0 |