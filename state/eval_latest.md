# Watchtower Pipeline Eval — 2026-04-30T22:04:46Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 318 |
| After dedup + CVE merge | 316 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/318 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,654 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8218

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 109 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 164 |
| `bsi_germany` | 103 |
| `bleepingcomputer` | 10 |
| `securityweek` | 9 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-25 | 5 | ? | 100% | 0% | 5 | 0 |
| 2026-04-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-26 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-28 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-29 | 3 | 1 | 100% | 33% | 2 | 0 |