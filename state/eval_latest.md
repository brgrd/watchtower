# Watchtower Pipeline Eval — 2026-11-21T23:03:01Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 392 |
| After dedup + CVE merge | 387 |
| Sent to Groq | 4 |
| Groq findings returned | 0 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/392 (1.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**4 cards** — P1: 0, P2: 0, P3: 4

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 55 / 60 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **2** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 3.8 | Mean shelf_days: 11

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 351 |
| `gcp_security` | 30 |
| `thehackernews` | 5 |
| `bleepingcomputer` | 4 |
| `krebs` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-16 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-17 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-17 | 9 | ? | 0% | 0% | 4 | 2 |
| 2026-11-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-19 | 6 | ? | 0% | 0% | 3 | 1 |
| 2026-11-20 | 8 | ? | 0% | 0% | 8 | 0 |
| 2026-11-21 | 15 | ? | 0% | 0% | 14 | 0 |