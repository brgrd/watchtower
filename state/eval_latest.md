# Watchtower Pipeline Eval — 2026-05-28T12:39:24Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 554 |
| After dedup + CVE merge | 554 |
| Sent to Groq | 3 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/554 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,229 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8083

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 71.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 3 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 209 |
| `bsi_germany` | 180 |
| `msrc_update_guide` | 147 |
| `securityweek` | 4 |
| `bleepingcomputer` | 3 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-24 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-25 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-05-26 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-26 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-05-27 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-27 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-27 | 3 | ? | 100% | 0% | 3 | 0 |