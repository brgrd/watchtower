# Watchtower Pipeline Eval — 2026-04-28T22:08:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 390 |
| After dedup + CVE merge | 389 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/390 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,857 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7880

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 30.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 225 |
| `bsi_germany` | 109 |
| `bleepingcomputer` | 11 |
| `securityweek` | 10 |
| `thehackernews` | 9 |
| _(+19 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-24 | 5 | 5 | 100% | 0% | 5 | 0 |
| 2026-04-25 | 3 | 3 | 100% | 0% | 1 | 0 |
| 2026-04-25 | 5 | ? | 100% | 0% | 5 | 0 |
| 2026-04-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-26 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-27 | 3 | ? | 100% | 0% | 3 | 0 |