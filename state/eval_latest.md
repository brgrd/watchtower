# Watchtower Pipeline Eval — 2026-11-10T00:11:20Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 734 |
| After dedup + CVE merge | 728 |
| Sent to Groq | 5 |
| Groq findings returned | 0 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/734 (0.7%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**5 cards** — P1: 0, P2: 0, P3: 5

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 61 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.6 | Mean shelf_days: 1.6

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 472 |
| `bsi_germany` | 204 |
| `bleepingcomputer` | 12 |
| `thehackernews` | 11 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-04 | 11 | ? | 0% | 0% | 8 | 1 |
| 2026-11-04 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-11-05 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-11-06 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-11-06 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-11-08 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-11-08 | 15 | ? | 0% | 0% | 15 | 0 |