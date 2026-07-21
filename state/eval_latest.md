# Watchtower Pipeline Eval — 2026-07-21T00:04:59Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 296 |
| After dedup + CVE merge | 296 |
| Sent to Groq | 12 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/296 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,888 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7231

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 43.3 / 45 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 61 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 0.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 245 |
| `msrc_update_guide` | 18 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 5 |
| `therecord` | 5 |
| _(+21 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-19 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | ? | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | 2 | 100% | 0% | 3 | 0 |