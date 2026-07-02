# Watchtower Pipeline Eval — 2026-07-02T09:28:48Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 265 |
| After dedup + CVE merge | 264 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/265 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,811 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7331

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 51.7 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 55 chars (67% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 12.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 142 |
| `nvd` | 111 |
| `github_changelog` | 4 |
| `thehackernews` | 4 |
| `bleepingcomputer` | 3 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-01 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-02 | 2 | 1 | 100% | 50% | 1 | 0 |