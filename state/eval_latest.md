# Watchtower Pipeline Eval — 2026-06-23T21:04:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 328 |
| After dedup + CVE merge | 301 |
| Sent to Groq | 27 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/328 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,370 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7050

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 33 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 2 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 186 |
| `bsi_germany` | 58 |
| `gcp_security` | 30 |
| `securityweek` | 9 |
| `cisa_alerts` | 8 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-21 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-21 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-21 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 4 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-23 | 12 | ? | 0% | 0% | 12 | 0 |