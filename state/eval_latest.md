# Watchtower Pipeline Eval — 2026-09-30T23:40:32Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 779 |
| After dedup + CVE merge | 772 |
| Sent to Groq | 3 |
| Groq findings returned | 0 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/779 (0.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**3 cards** — P1: 0, P2: 0, P3: 3

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 73.3 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 14

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 199 |
| `msrc_update_guide` | 17 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 10 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-25 | 9 | ? | 0% | 0% | 3 | 0 |
| 2026-09-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-26 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-27 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-28 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-28 | 5 | ? | 0% | 0% | 1 | 1 |
| 2026-09-30 | 7 | ? | 0% | 0% | 7 | 0 |