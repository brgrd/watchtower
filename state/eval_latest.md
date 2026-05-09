# Watchtower Pipeline Eval — 2026-05-09T22:58:22Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 115 |
| After dedup + CVE merge | 115 |
| Sent to Groq | 27 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/115 (1.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,070 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7268

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 31 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 0.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 108 |
| `msrc_update_guide` | 3 |
| `bleepingcomputer` | 2 |
| `cisa_kev` | 1 |
| `thehackernews` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-08 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-08 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |