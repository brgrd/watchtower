# Watchtower Pipeline Eval — 2026-08-10T21:52:06Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 694 |
| After dedup + CVE merge | 694 |
| Sent to Groq | 21 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/694 (0.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,603 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7684

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 62 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 138 |
| `msrc_update_guide` | 9 |
| `bleepingcomputer` | 8 |
| `securityweek` | 7 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-09 | 3 | 1 | 100% | 67% | 3 | 0 |
| 2026-08-09 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-08-09 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-09 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-09 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |