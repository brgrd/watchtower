# Watchtower Pipeline Eval — 2026-08-11T21:57:35Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 1077 |
| After dedup + CVE merge | 863 |
| Sent to Groq | 8 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/1077 (0.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 15,025 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6475

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 57.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 33% specific, 67% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `msrc_update_guide` | 440 |
| `bsi_germany` | 46 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 12 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-08-11 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-11 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-11 | 3 | 2 | 100% | 0% | 3 | 0 |