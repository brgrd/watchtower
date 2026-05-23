# Watchtower Pipeline Eval — 2026-05-23T22:04:36Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 34 |
| After dedup + CVE merge | 34 |
| Sent to Groq | 6 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/34 (8.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,736 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6476

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 80 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 89.7 chars (67% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 33% generic

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
| `msrc_update_guide` | 24 |
| `thehackernews` | 4 |
| `bleepingcomputer` | 2 |
| `darkreading` | 2 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-20 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-21 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-05-23 | 3 | 3 | 100% | 100% | 3 | 0 |