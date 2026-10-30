# Watchtower Pipeline Eval — 2026-10-30T00:47:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 797 |
| After dedup + CVE merge | 789 |
| Sent to Groq | 6 |
| Groq findings returned | 0 |
| Final cards rendered | 6 |
| **Pipeline yield** | **6/797 (0.8%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**6 cards** — P1: 0, P2: 0, P3: 6

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 67.5 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 6 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **3** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 1.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 17% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 228 |
| `thehackernews` | 14 |
| `bleepingcomputer` | 13 |
| `securityweek` | 10 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-25 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 3 | ? | 0% | 0% | 1 | 0 |
| 2026-10-27 | 1 | ? | 0% | 0% | 0 | 1 |
| 2026-10-27 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-10-29 | 8 | ? | 0% | 0% | 7 | 0 |