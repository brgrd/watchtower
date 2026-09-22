# Watchtower Pipeline Eval — 2026-09-22T21:59:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 686 |
| After dedup + CVE merge | 670 |
| Sent to Groq | 9 |
| Groq findings returned | 0 |
| Final cards rendered | 9 |
| **Pipeline yield** | **9/686 (1.3%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**9 cards** — P1: 0, P2: 0, P3: 9

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 57.8 / 80 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 9 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **8** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.2 | Mean shelf_days: 1.2

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 382 |
| `bsi_germany` | 224 |
| `bleepingcomputer` | 12 |
| `thehackernews` | 12 |
| `cisa_alerts` | 10 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-19 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-20 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-21 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-21 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-22 | 2 | ? | 0% | 0% | 1 | 0 |