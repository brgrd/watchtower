# Watchtower Pipeline Eval — 2026-08-26T23:21:01Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 474 |
| After dedup + CVE merge | 468 |
| Sent to Groq | 8 |
| Groq findings returned | 0 |
| Final cards rendered | 8 |
| **Pipeline yield** | **8/474 (1.7%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**8 cards** — P1: 0, P2: 0, P3: 8

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 63.1 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 8 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **2** | Persistent (>5): **3** | Resolved: **0**
- Mean run_count: 4.1 | Mean shelf_days: 54.1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 290 |
| `bsi_germany` | 102 |
| `gcp_security` | 31 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 7 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-26 | 12 | ? | 0% | 0% | 12 | 0 |