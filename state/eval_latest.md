# Watchtower Pipeline Eval — 2026-08-13T22:54:48Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 650 |
| After dedup + CVE merge | 646 |
| Sent to Groq | 4 |
| Groq findings returned | 4 |
| Passed quality gate | 4 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/650 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,852 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7363

## Card Quality

**4 cards** — P1: 4, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 77.5 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 52.2 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 8 total — 62% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 500 |
| `bsi_germany` | 74 |
| `msrc_update_guide` | 28 |
| `cisa_alerts` | 14 |
| `bleepingcomputer` | 10 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-12 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-08-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-12 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-08-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-13 | 3 | 2 | 100% | 67% | 3 | 0 |