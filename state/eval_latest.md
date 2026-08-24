# Watchtower Pipeline Eval — 2026-08-24T22:36:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 339 |
| After dedup + CVE merge | 333 |
| Sent to Groq | 27 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/339 (4.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 42.7 / 40 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **14** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 7% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 260 |
| `bsi_germany` | 44 |
| `bleepingcomputer` | 8 |
| `thehackernews` | 6 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-23 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-23 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-08-23 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-08-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-24 | 15 | ? | 0% | 0% | 15 | 0 |