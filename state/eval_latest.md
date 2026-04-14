# Watchtower Pipeline Eval — 2026-04-14T22:00:12Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 473 |
| After dedup + CVE merge | 472 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/473 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,733 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8252

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 60.7 chars (33% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 40% specific, 0% generic

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
| `nvd` | 304 |
| `bsi_germany` | 124 |
| `bleepingcomputer` | 9 |
| `securityweek` | 8 |
| `github_changelog` | 7 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-10 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-11 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-11 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-13 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-14 | 3 | 3 | 100% | 100% | 0 | 0 |