# Watchtower Pipeline Eval — 2026-06-11T00:25:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 245 |
| After dedup + CVE merge | 241 |
| Sent to Groq | 22 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/245 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,320 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6506

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 67% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

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
| `nvd` | 204 |
| `msrc_update_guide` | 8 |
| `bleepingcomputer` | 7 |
| `darkreading` | 6 |
| `thehackernews` | 4 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-08 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-09 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-09 | 15 | ? | 0% | 0% | 6 | 0 |
| 2026-06-09 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-06-10 | 2 | 2 | 100% | 0% | 0 | 0 |
| 2026-06-10 | 2 | 2 | 100% | 100% | 2 | 0 |