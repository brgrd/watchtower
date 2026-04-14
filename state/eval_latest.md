# Watchtower Pipeline Eval — 2026-04-14T22:56:58Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 376 |
| After dedup + CVE merge | 375 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/376 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,727 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8243

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 77.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 40% specific, 60% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 67% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 316 |
| `bsi_germany` | 17 |
| `bleepingcomputer` | 10 |
| `github_changelog` | 7 |
| `securityweek` | 5 |
| _(+19 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-11 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-11 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-13 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-14 | 3 | 3 | 100% | 100% | 0 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |