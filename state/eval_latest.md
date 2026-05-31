# Watchtower Pipeline Eval — 2026-05-31T00:10:40Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 43 |
| After dedup + CVE merge | 43 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/43 (7.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,759 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7418

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 106.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 37 |
| `bleepingcomputer` | 2 |
| `securityweek` | 2 |
| `darkreading` | 2 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-29 | 3 | 1 | 67% | 100% | 3 | 0 |
| 2026-05-29 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-29 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-30 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-05-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-30 | 3 | 3 | 100% | 0% | 3 | 0 |