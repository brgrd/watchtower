# Watchtower Pipeline Eval — 2026-06-15T21:15:21Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 245 |
| After dedup + CVE merge | 240 |
| Sent to Groq | 16 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/245 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,856 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7170

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 116.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 151 |
| `bsi_germany` | 38 |
| `msrc_update_guide` | 14 |
| `bleepingcomputer` | 10 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-13 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-14 | 5 | 1 | 100% | 20% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-15 | 3 | 3 | 100% | 0% | 3 | 0 |