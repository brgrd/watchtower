# Watchtower Pipeline Eval — 2026-05-01T22:01:24Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 348 |
| After dedup + CVE merge | 347 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/348 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,242 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8333

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 59 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 305 |
| `securityweek` | 8 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 6 |
| `therecord` | 5 |
| _(+19 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-26 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-28 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-29 | 3 | 1 | 100% | 33% | 2 | 0 |
| 2026-04-30 | 3 | 1 | 100% | 100% | 3 | 0 |