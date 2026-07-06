# Watchtower Pipeline Eval — 2026-07-06T22:21:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 386 |
| After dedup + CVE merge | 385 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/386 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,335 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6487

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 69.5 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 181 |
| `nvd` | 170 |
| `thehackernews` | 9 |
| `securityweek` | 6 |
| `bleepingcomputer` | 5 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-04 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-04 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-04 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-05 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 3 | ? | 100% | 0% | 3 | 0 |