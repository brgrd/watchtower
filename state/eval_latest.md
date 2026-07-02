# Watchtower Pipeline Eval — 2026-07-02T00:17:33Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 332 |
| After dedup + CVE merge | 329 |
| Sent to Groq | 29 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/332 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 15,661 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6202

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 31 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 18.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 282 |
| `github_changelog` | 10 |
| `thehackernews` | 9 |
| `bleepingcomputer` | 8 |
| `cloudflare_blog` | 4 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-01 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 100% | 3 | 0 |