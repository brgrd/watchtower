# Watchtower Pipeline Eval — 2026-05-13T00:10:20Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 648 |
| After dedup + CVE merge | 521 |
| Sent to Groq | 7 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/648 (0.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,625 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6579

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 36 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 0% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 448 |
| `msrc_update_guide` | 121 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 10 |
| `securityweek` | 10 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-09 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-11 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-05-11 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-05-12 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-05-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-12 | 1 | 1 | 100% | 100% | 1 | 0 |