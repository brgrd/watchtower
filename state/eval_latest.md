# Watchtower Pipeline Eval — 2026-05-19T21:40:24Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 283 |
| After dedup + CVE merge | 279 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/283 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,948 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6940

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 83.3 / 80 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 113.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 144 |
| `bsi_germany` | 91 |
| `bleepingcomputer` | 10 |
| `securityweek` | 8 |
| `cisa_alerts` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-17 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-17 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-18 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-18 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 3 | 100% | 0% | 3 | 0 |