# Watchtower Pipeline Eval — 2026-05-08T21:15:18Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 469 |
| After dedup + CVE merge | 466 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/469 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,844 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7622

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 298 |
| `bsi_germany` | 141 |
| `bleepingcomputer` | 5 |
| `thehackernews` | 5 |
| `therecord` | 5 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-07 | 3 | 2 | 100% | 67% | 2 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-08 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |