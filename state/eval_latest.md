# Watchtower Pipeline Eval — 2026-04-25T22:50:44Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 29 |
| After dedup + CVE merge | 29 |
| Sent to Groq | 29 |
| Groq findings returned | 5 |
| Passed quality gate | 5 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/29 (17.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,099 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8125

## Card Quality

**5 cards** — P1: 0, P2: 5, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 10 total — 50% specific, 50% generic

### Persistence

- New (run=1): **5** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 26 |
| `bleepingcomputer` | 2 |
| `securityweek` | 1 |
| `cisa_alerts` | 0 |
| `cisa_kev` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-22 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-22 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-04-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-04-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-04-24 | 5 | 5 | 100% | 0% | 5 | 0 |
| 2026-04-25 | 3 | 3 | 100% | 0% | 1 | 0 |