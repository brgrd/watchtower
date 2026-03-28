# Watchtower Pipeline Eval — 2026-03-28T10:44:28Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 43 |
| After dedup + CVE merge | 42 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/43 (7.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,694 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10176

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 81.7 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 52 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 38 |
| `thehackernews` | 3 |
| `cisa_kev` | 1 |
| `securityweek` | 1 |
| `bleepingcomputer` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-24 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-03-24 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |