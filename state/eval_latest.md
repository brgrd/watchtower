# Watchtower Pipeline Eval — 2026-08-24T21:37:35Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 407 |
| After dedup + CVE merge | 406 |
| Sent to Groq | 27 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/407 (3.7%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 46 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **15** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 8 | 53% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 244 |
| `bsi_germany` | 126 |
| `bleepingcomputer` | 9 |
| `securityweek` | 7 |
| `thehackernews` | 6 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-23 | ? | ? | ?% | ?% | ? | ? |
| 2026-08-23 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-23 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-08-23 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-08-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-24 | 15 | ? | 0% | 0% | 15 | 0 |