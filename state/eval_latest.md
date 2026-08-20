# Watchtower Pipeline Eval — 2026-08-20T21:36:42Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 491 |
| After dedup + CVE merge | 486 |
| Sent to Groq | 24 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/491 (3.1%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56.7 / 70 |
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
| EPSS | 1 | 7% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 318 |
| `bsi_germany` | 111 |
| `thehackernews` | 13 |
| `securityweek` | 8 |
| `msrc_update_guide` | 8 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |