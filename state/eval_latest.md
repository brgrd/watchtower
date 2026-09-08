# Watchtower Pipeline Eval — 2026-09-08T21:46:45Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 1695 |
| After dedup + CVE merge | 1396 |
| Sent to Groq | 6 |
| Groq findings returned | 0 |
| Final cards rendered | 6 |
| **Pipeline yield** | **6/1695 (0.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**6 cards** — P1: 0, P2: 0, P3: 6

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 57.5 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 6 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **2** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 2.7 | Mean shelf_days: 30

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 1023 |
| `nvd` | 500 |
| `bsi_germany` | 79 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 15 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-05 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-07 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-07 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-08 | 15 | ? | 0% | 0% | 15 | 0 |