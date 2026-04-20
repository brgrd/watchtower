# Watchtower Pipeline Eval — 2026-04-20T22:57:11Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 329 |
| After dedup + CVE merge | 328 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/329 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,704 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7920

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 3 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 170 |
| `bsi_germany` | 103 |
| `bleepingcomputer` | 10 |
| `cisa_kev` | 8 |
| `securityweek` | 8 |
| _(+19 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-17 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-17 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-04-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-19 | 3 | 1 | 100% | 100% | 3 | 0 |