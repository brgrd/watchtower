# Watchtower Pipeline Eval — 2026-04-11T22:46:14Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 5 |
| After dedup + CVE merge | 5 |
| Sent to Groq | 5 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/5 (60.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 4,949 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8748

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 75% generic

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
| `nvd` | 4 |
| `bleepingcomputer` | 1 |
| `cisa_alerts` | 0 |
| `cisa_kev` | 0 |
| `krebs` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-05 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-06 | 3 | 2 | 67% | 0% | 3 | 0 |
| 2026-04-07 | 5 | 2 | 100% | 40% | 5 | 0 |
| 2026-04-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-09 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-04-10 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-11 | 3 | 2 | 100% | 0% | 3 | 0 |