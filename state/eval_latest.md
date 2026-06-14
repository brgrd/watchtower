# Watchtower Pipeline Eval — 2026-06-14T23:21:10Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 15 |
| After dedup + CVE merge | 15 |
| Sent to Groq | 15 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/15 (20.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,970 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6927

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
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `nvd` | 12 |
| `bleepingcomputer` | 1 |
| `darkreading` | 1 |
| `snyk_blog` | 1 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-12 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-06-13 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-13 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-14 | 5 | 1 | 100% | 20% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-14 | 3 | 2 | 100% | 0% | 3 | 0 |