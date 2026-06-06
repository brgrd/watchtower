# Watchtower Pipeline Eval — 2026-06-06T22:12:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 19 |
| After dedup + CVE merge | 19 |
| Sent to Groq | 19 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/19 (10.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,206 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6641

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 18 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 0% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 15 |
| `bleepingcomputer` | 1 |
| `thehackernews` | 1 |
| `securityweek` | 1 |
| `darkreading` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-04 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-04 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-05 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-05 | 15 | ? | 0% | 0% | 13 | 0 |
| 2026-06-06 | 15 | ? | 0% | 0% | 11 | 0 |
| 2026-06-06 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-06 | 15 | ? | 0% | 0% | 15 | 0 |