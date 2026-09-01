# Watchtower Pipeline Eval — 2026-09-01T21:42:59Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 672 |
| After dedup + CVE merge | 658 |
| Sent to Groq | 9 |
| Groq findings returned | 0 |
| Final cards rendered | 9 |
| **Pipeline yield** | **9/672 (1.3%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**9 cards** — P1: 0, P2: 0, P3: 9

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 9 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **9** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 370 |
| `bsi_germany` | 250 |
| `securityweek` | 10 |
| `bleepingcomputer` | 8 |
| `darkreading` | 7 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-27 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-08-29 | 10 | ? | 0% | 0% | 10 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-31 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 2 | ? | 0% | 0% | 2 | 0 |