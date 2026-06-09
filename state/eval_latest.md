# Watchtower Pipeline Eval — 2026-06-09T23:24:54Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 844 |
| After dedup + CVE merge | 625 |
| Sent to Groq | 8 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/844 (0.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,034 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6648

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `msrc_update_guide` | 261 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 10 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-07 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 1 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-09 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-09 | 15 | ? | 0% | 0% | 6 | 0 |