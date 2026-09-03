# Watchtower Pipeline Eval — 2026-09-03T21:39:19Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 479 |
| After dedup + CVE merge | 474 |
| Sent to Groq | 9 |
| Groq findings returned | 0 |
| Final cards rendered | 9 |
| **Pipeline yield** | **9/479 (1.9%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**9 cards** — P1: 0, P2: 0, P3: 9

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 59.4 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 9 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **8** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 1.6

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 291 |
| `bsi_germany` | 124 |
| `cisa_alerts` | 11 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 8 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-01 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 9 | ? | 0% | 0% | 9 | 0 |
| 2026-09-02 | 2 | ? | 0% | 0% | 0 | 0 |
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-03 | 5 | ? | 0% | 0% | 4 | 0 |