# Watchtower Pipeline Eval — 2026-07-01T22:23:56Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 375 |
| After dedup + CVE merge | 371 |
| Sent to Groq | 27 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/375 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 16,553 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6014

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 229 |
| `bsi_germany` | 84 |
| `thehackernews` | 11 |
| `bleepingcomputer` | 10 |
| `github_changelog` | 7 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-30 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-01 | 1 | 1 | 100% | 100% | 1 | 0 |