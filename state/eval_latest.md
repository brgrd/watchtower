# Watchtower Pipeline Eval — 2026-05-14T23:06:28Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 315 |
| After dedup + CVE merge | 305 |
| Sent to Groq | 26 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/315 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 15,299 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6449

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 78 chars (100% ≥ 60 chars, considered substantive)
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
| `nvd` | 248 |
| `cisa_alerts` | 18 |
| `bleepingcomputer` | 8 |
| `thehackernews` | 6 |
| `securityweek` | 6 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-12 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-13 | 1 | 1 | 100% | 0% | 0 | 0 |
| 2026-05-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-13 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |