# Watchtower Pipeline Eval — 2026-07-22T09:33:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 692 |
| After dedup + CVE merge | 687 |
| Sent to Groq | 6 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/692 (0.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,781 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7888

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 46.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 149 |
| `msrc_update_guide` | 24 |
| `bleepingcomputer` | 4 |
| `thehackernews` | 4 |
| _(+21 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-20 | 3 | ? | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | ? | 100% | 0% | 1 | 0 |
| 2026-07-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-21 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 14 | 0 |