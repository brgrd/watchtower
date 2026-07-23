# Watchtower Pipeline Eval — 2026-07-23T23:06:25Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 373 |
| After dedup + CVE merge | 370 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/373 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,032 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6721

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 84.5 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 0% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 305 |
| `bsi_germany` | 18 |
| `bleepingcomputer` | 9 |
| `cisa_alerts` | 8 |
| `thehackernews` | 7 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 6 | 1 |
| 2026-07-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-23 | 3 | 2 | 67% | 67% | 3 | 0 |