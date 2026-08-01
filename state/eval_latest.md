# Watchtower Pipeline Eval — 2026-08-01T22:07:44Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 79 |
| After dedup + CVE merge | 78 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/79 (3.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,594 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7642

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 69.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 75 |
| `securityweek` | 2 |
| `bleepingcomputer` | 1 |
| `thehackernews` | 1 |
| `cisa_kev` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-31 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-31 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-31 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-07-31 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-08-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-01 | 3 | 1 | 100% | 0% | 3 | 0 |