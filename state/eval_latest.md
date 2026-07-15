# Watchtower Pipeline Eval — 2026-07-14T23:59:53Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 1128 |
| After dedup + CVE merge | 753 |
| Sent to Groq | 5 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/1128 (0.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,269 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6978

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 80 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 55 chars (33% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 0.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 573 |
| `nvd` | 500 |
| `bleepingcomputer` | 11 |
| `cisa_alerts` | 6 |
| `thehackernews` | 6 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-07-14 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-14 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 100% | 2 | 0 |