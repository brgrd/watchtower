# Watchtower Pipeline Eval — 2026-03-26T22:44:39Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 521 |
| After dedup + CVE merge | 520 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/521 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,450 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10301

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 26.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 33% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 304 |
| `bsi_germany` | 162 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 7 |
| `github_changelog` | 7 |
| _(+19 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-22 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-23 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-03-24 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-03-24 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 1 | 100% | 0% | 3 | 0 |