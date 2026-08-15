# Watchtower Pipeline Eval — 2026-08-15T09:34:20Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 507 |
| After dedup + CVE merge | 507 |
| Sent to Groq | 25 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/507 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,594 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7677

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 41.7 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 54 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `msrc_update_guide` | 5 |
| `bleepingcomputer` | 1 |
| `github_changelog` | 1 |
| `gh_security_blog` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-13 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-08-13 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-08-14 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-14 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-14 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-14 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-14 | 3 | 3 | 100% | 0% | 3 | 0 |