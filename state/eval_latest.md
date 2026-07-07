# Watchtower Pipeline Eval — 2026-07-07T00:16:32Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 142 |
| After dedup + CVE merge | 140 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/142 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,970 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7079

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 76 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 114 |
| `bleepingcomputer` | 5 |
| `securityweek` | 5 |
| `therecord` | 5 |
| `thehackernews` | 4 |
| _(+21 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-04 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-04 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-05 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-06 | 2 | 2 | 100% | 100% | 2 | 0 |