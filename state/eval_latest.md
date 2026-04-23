# Watchtower Pipeline Eval — 2026-04-23T10:41:28Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 201 |
| After dedup + CVE merge | 201 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/201 (1.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,469 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8310

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 76.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 119 |
| `nvd` | 68 |
| `thehackernews` | 3 |
| `github_changelog` | 3 |
| `securityweek` | 3 |
| _(+19 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-19 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-04-20 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-21 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-22 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-22 | 3 | 2 | 100% | 33% | 3 | 0 |