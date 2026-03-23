# Watchtower Pipeline Eval — 2026-03-23T22:46:28Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 311 |
| After dedup + CVE merge | 311 |
| Sent to Groq | 29 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/311 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,223 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10293

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 54 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `nvd` | 192 |
| `bsi_germany` | 68 |
| `bleepingcomputer` | 10 |
| `securityweek` | 7 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-19 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-20 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-03-20 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-03-21 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-03-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-22 | 3 | 1 | 100% | 0% | 3 | 0 |