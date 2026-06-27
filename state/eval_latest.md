# Watchtower Pipeline Eval — 2026-06-27T22:12:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 5 |
| After dedup + CVE merge | 5 |
| Sent to Groq | 5 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/5 (60.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,333 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6944

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 118.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 17% generic

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
| `thehackernews` | 2 |
| `bleepingcomputer` | 1 |
| `securityweek` | 1 |
| `darkreading` | 1 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-26 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-26 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-26 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-27 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-27 | 3 | ? | 100% | 0% | 3 | 0 |