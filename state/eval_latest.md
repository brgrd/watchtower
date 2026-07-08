# Watchtower Pipeline Eval — 2026-07-08T21:19:02Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 292 |
| After dedup + CVE merge | 291 |
| Sent to Groq | 28 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/292 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,832 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7350

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
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
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 232 |
| `bsi_germany` | 18 |
| `thehackernews` | 8 |
| `bleepingcomputer` | 7 |
| `securityweek` | 6 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-06 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-07-07 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-07 | 15 | ? | 0% | 0% | 4 | 1 |
| 2026-07-07 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-08 | 2 | 1 | 100% | 50% | 2 | 0 |