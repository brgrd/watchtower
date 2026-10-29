# Watchtower Pipeline Eval — 2026-10-29T00:46:43Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 963 |
| After dedup + CVE merge | 955 |
| Sent to Groq | 8 |
| Groq findings returned | 0 |
| Final cards rendered | 8 |
| **Pipeline yield** | **8/963 (0.8%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**8 cards** — P1: 0, P2: 0, P3: 8

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 58.1 / 80 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 8 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **7** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.2 | Mean shelf_days: 4.1

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
| `msrc_update_guide` | 299 |
| `bsi_germany` | 53 |
| `gcp_security` | 30 |
| `thehackernews` | 15 |
| _(+21 more)_ | … |

**7 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-25 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 3 | ? | 0% | 0% | 1 | 0 |
| 2026-10-27 | 1 | ? | 0% | 0% | 0 | 1 |
| 2026-10-27 | 6 | ? | 0% | 0% | 5 | 0 |