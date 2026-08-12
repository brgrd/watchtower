# Watchtower Pipeline Eval — 2026-08-12T10:15:42Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 347 |
| After dedup + CVE merge | 345 |
| Sent to Groq | 4 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/347 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,381 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6986

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 96.7 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 31.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 83% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 4.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 180 |
| `nvd` | 110 |
| `msrc_update_guide` | 38 |
| `securityweek` | 6 |
| `thehackernews` | 5 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-10 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-08-11 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-11 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-11 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-11 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-08-11 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-11 | 2 | 1 | 100% | 0% | 2 | 0 |