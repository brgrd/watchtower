# Watchtower Pipeline Eval — 2026-06-11T21:27:56Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 343 |
| After dedup + CVE merge | 340 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/343 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,879 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7252

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 60 chars (50% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 168 |
| `nvd` | 130 |
| `securityweek` | 9 |
| `thehackernews` | 8 |
| `github_changelog` | 6 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-09 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-09 | 15 | ? | 0% | 0% | 6 | 0 |
| 2026-06-09 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-06-10 | 2 | 2 | 100% | 0% | 0 | 0 |
| 2026-06-10 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-11 | 3 | 2 | 67% | 0% | 3 | 0 |
| 2026-06-11 | 3 | 3 | 100% | 0% | 3 | 0 |