# Watchtower Pipeline Eval — 2026-06-24T12:25:27Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 294 |
| After dedup + CVE merge | 262 |
| Sent to Groq | 29 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/294 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,695 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7457

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 62 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `bsi_germany` | 155 |
| `nvd` | 95 |
| `gcp_security` | 30 |
| `securityweek` | 7 |
| `thehackernews` | 2 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-22 | 15 | ? | 0% | 0% | 4 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-23 | 12 | ? | 0% | 0% | 12 | 0 |
| 2026-06-23 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-23 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 10 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |