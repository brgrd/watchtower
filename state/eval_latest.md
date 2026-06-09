# Watchtower Pipeline Eval — 2026-06-09T12:12:54Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 427 |
| After dedup + CVE merge | 424 |
| Sent to Groq | 3 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/427 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,069 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7620

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 60 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 206 |
| `bsi_germany` | 151 |
| `msrc_update_guide` | 54 |
| `thehackernews` | 4 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-07 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 1 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 100% | 3 | 0 |