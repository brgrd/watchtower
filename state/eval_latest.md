# Watchtower Pipeline Eval — 2026-11-20T11:21:06Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 900 |
| After dedup + CVE merge | 889 |
| Sent to Groq | 8 |
| Groq findings returned | 0 |
| Final cards rendered | 8 |
| **Pipeline yield** | **8/900 (0.9%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**8 cards** — P1: 0, P2: 0, P3: 8

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60.6 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 8 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **8** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 12% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 250 |
| `msrc_update_guide` | 60 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 11 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-14 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-15 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-11-16 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-17 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-17 | 9 | ? | 0% | 0% | 4 | 2 |
| 2026-11-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-19 | 6 | ? | 0% | 0% | 3 | 1 |