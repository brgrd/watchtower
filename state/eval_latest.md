# Watchtower Pipeline Eval — 2026-03-20T22:40:09Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 173 |
| After dedup + CVE merge | 173 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/173 (1.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,360 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 9806

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 34 chars (0% ≥ 60 chars, considered substantive)
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
| `nvd` | 111 |
| `bsi_germany` | 21 |
| `securityweek` | 7 |
| `bleepingcomputer` | 5 |
| `cisa_kev` | 5 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-18 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-03-18 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-03-18 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-03-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-19 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-20 | 2 | 1 | 100% | 0% | 1 | 0 |