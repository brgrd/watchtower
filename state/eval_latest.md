# Watchtower Pipeline Eval — 2026-06-15T23:55:58Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 493 |
| After dedup + CVE merge | 488 |
| Sent to Groq | 2 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/493 (0.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,743 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7769

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 56 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 50% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 1 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 367 |
| `msrc_update_guide` | 87 |
| `bleepingcomputer` | 11 |
| `thehackernews` | 5 |
| `darkreading` | 5 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-14 | 5 | 1 | 100% | 20% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-15 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-15 | 3 | 3 | 100% | 33% | 3 | 0 |