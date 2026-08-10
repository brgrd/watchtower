# Watchtower Pipeline Eval — 2026-08-10T10:25:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 136 |
| After dedup + CVE merge | 136 |
| Sent to Groq | 12 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/136 (2.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,594 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7640

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
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 109 |
| `msrc_update_guide` | 18 |
| `securityweek` | 4 |
| `thehackernews` | 2 |
| `bsi_germany` | 2 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-09 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-09 | 3 | 1 | 100% | 67% | 3 | 0 |
| 2026-08-09 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-08-09 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-09 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-09 | 3 | 2 | 100% | 0% | 3 | 0 |