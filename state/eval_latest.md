# Watchtower Pipeline Eval — 2026-09-11T22:28:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 709 |
| After dedup + CVE merge | 692 |
| Sent to Groq | 7 |
| Groq findings returned | 0 |
| Final cards rendered | 7 |
| **Pipeline yield** | **7/709 (1.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**7 cards** — P1: 0, P2: 0, P3: 7

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 52.9 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 7 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **7** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 500 |
| `bsi_germany` | 90 |
| `msrc_update_guide` | 43 |
| `gcp_security` | 30 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-09 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-09-09 | 15 | ? | 0% | 0% | 3 | 0 |
| 2026-09-10 | 11 | ? | 0% | 0% | 4 | 0 |
| 2026-09-10 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-10 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-09-11 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-11 | 1 | ? | 0% | 0% | 0 | 0 |