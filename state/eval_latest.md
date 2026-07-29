# Watchtower Pipeline Eval — 2026-07-29T10:46:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 245 |
| After dedup + CVE merge | 245 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/245 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,046 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7028

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 102 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `bsi_germany` | 128 |
| `nvd` | 102 |
| `thehackernews` | 5 |
| `securityweek` | 5 |
| `github_changelog` | 3 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-27 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-29 | 3 | 3 | 100% | 0% | 3 | 0 |