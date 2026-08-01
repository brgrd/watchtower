# Watchtower Pipeline Eval — 2026-08-01T21:04:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 111 |
| After dedup + CVE merge | 110 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/111 (2.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,619 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7691

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 79 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 107 |
| `securityweek` | 2 |
| `bleepingcomputer` | 1 |
| `thehackernews` | 1 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-31 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-31 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-31 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-07-31 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-08-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-01 | 3 | 3 | 100% | 0% | 3 | 0 |