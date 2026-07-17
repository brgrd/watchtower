# Watchtower Pipeline Eval — 2026-07-17T10:07:21Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 277 |
| After dedup + CVE merge | 276 |
| Sent to Groq | 15 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/277 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,307 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7193

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 54 chars (0% ≥ 60 chars, considered substantive)
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
| `bsi_germany` | 138 |
| `nvd` | 110 |
| `msrc_update_guide` | 15 |
| `securityweek` | 4 |
| `bleepingcomputer` | 3 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-15 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-15 | 3 | 2 | 100% | 0% | 2 | 0 |
| 2026-07-16 | 3 | 2 | 100% | 33% | 1 | 0 |
| 2026-07-16 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-16 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-17 | 3 | 3 | 100% | 0% | 2 | 0 |