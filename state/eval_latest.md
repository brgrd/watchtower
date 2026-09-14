# Watchtower Pipeline Eval — 2026-09-14T23:04:07Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 1003 |
| After dedup + CVE merge | 999 |
| Sent to Groq | 3 |
| Groq findings returned | 0 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/1003 (0.3%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**3 cards** — P1: 0, P2: 0, P3: 3

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 58.3 / 65 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 250 |
| `msrc_update_guide` | 208 |
| `bleepingcomputer` | 12 |
| `securityweek` | 9 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-11 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-09-12 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-12 | 2 | ? | 0% | 0% | 0 | 0 |
| 2026-09-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-13 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-14 | 15 | ? | 0% | 0% | 15 | 0 |