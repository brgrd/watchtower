# Watchtower Pipeline Eval — 2026-07-23T00:09:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 251 |
| After dedup + CVE merge | 237 |
| Sent to Groq | 25 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/251 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,020 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7347

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 30.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 182 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 6 |
| `securityweek` | 6 |
| `therecord` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-21 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 6 | 1 |