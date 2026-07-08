# Watchtower Pipeline Eval — 2026-07-08T00:07:57Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 147 |
| After dedup + CVE merge | 145 |
| Sent to Groq | 29 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/147 (2.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,737 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6800

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 6

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 3 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 107 |
| `bleepingcomputer` | 6 |
| `thehackernews` | 6 |
| `github_changelog` | 5 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-05 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-07-07 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-07 | 15 | ? | 0% | 0% | 4 | 1 |
| 2026-07-07 | 3 | 3 | 100% | 100% | 3 | 0 |