# Watchtower Pipeline Eval — 2026-07-29T21:07:22Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 421 |
| After dedup + CVE merge | 410 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/421 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 16,819 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 5915

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 200 |
| `bsi_germany` | 145 |
| `gcp_security` | 30 |
| `thehackernews` | 9 |
| `bleepingcomputer` | 7 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-27 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-29 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-29 | 2 | 2 | 100% | 0% | 2 | 0 |