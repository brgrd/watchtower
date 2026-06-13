# Watchtower Pipeline Eval — 2026-06-13T22:14:53Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 12 |
| After dedup + CVE merge | 12 |
| Sent to Groq | 12 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/12 (25.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 15,678 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6454

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 55 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 6 |
| `bleepingcomputer` | 2 |
| `thehackernews` | 1 |
| `securityweek` | 1 |
| `cyberscoop` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-11 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-11 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-11 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-12 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-12 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-06-12 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-06-13 | 3 | 1 | 100% | 0% | 3 | 0 |