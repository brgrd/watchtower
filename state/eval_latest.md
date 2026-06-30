# Watchtower Pipeline Eval — 2026-06-30T00:15:02Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 217 |
| After dedup + CVE merge | 213 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/217 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,119 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7079

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 43.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 183 |
| `bleepingcomputer` | 8 |
| `thehackernews` | 4 |
| `securityweek` | 4 |
| `darkreading` | 4 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-28 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-06-28 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-28 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-29 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-29 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-29 | 2 | 2 | 100% | 100% | 2 | 0 |