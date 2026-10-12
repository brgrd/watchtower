# Watchtower Pipeline Eval — 2026-10-12T09:03:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 241 |
| After dedup + CVE merge | 241 |
| Sent to Groq | 1 |
| Groq findings returned | 0 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/241 (0.4%)** |

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
- Mean run_count: 2 | Mean shelf_days: 3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 128 |
| `nvd` | 104 |
| `msrc_update_guide` | 6 |
| `securityweek` | 2 |
| `thehackernews` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-07 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-10-07 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-10-08 | 5 | ? | 0% | 0% | 4 | 0 |
| 2026-10-09 | 13 | ? | 0% | 0% | 7 | 0 |
| 2026-10-10 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |