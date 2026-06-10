# Watchtower Pipeline Eval — 2026-06-10T12:33:11Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 367 |
| After dedup + CVE merge | 366 |
| Sent to Groq | 2 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/367 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,981 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8138

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 46 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 180 |
| `nvd` | 122 |
| `msrc_update_guide` | 33 |
| `securityweek` | 9 |
| `bleepingcomputer` | 6 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-08 | 3 | 3 | 100% | 0% | 1 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-09 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-09 | 15 | ? | 0% | 0% | 6 | 0 |
| 2026-06-09 | 3 | 2 | 100% | 33% | 3 | 0 |