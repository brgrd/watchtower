# Watchtower Pipeline Eval — 2026-08-08T10:43:41Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 60 |
| After dedup + CVE merge | 59 |
| Sent to Groq | 1 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/60 (1.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,716 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7933

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 72 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 50% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 100% |
| NVD (CVE) | 1 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 40 |
| `msrc_update_guide` | 12 |
| `thehackernews` | 5 |
| `cisa_kev` | 1 |
| `github_changelog` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-08-07 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 5 | ? | 0% | 0% | 1 | 3 |
| 2026-08-08 | 3 | 3 | 100% | 0% | 3 | 0 |