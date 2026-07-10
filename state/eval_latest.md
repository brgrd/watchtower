# Watchtower Pipeline Eval — 2026-07-10T23:09:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 287 |
| After dedup + CVE merge | 285 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/287 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,729 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7412

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 59 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 0% specific, 50% generic

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
| `nvd` | 246 |
| `thehackernews` | 9 |
| `bleepingcomputer` | 8 |
| `darkreading` | 5 |
| `therecord` | 4 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-09 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-09 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 100% | 3 | 0 |