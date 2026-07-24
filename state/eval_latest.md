# Watchtower Pipeline Eval — 2026-07-24T21:14:58Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 232 |
| After dedup + CVE merge | 231 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/232 (1.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,824 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7380

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 143 |
| `bsi_germany` | 59 |
| `bleepingcomputer` | 8 |
| `thehackernews` | 7 |
| `securityweek` | 3 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-23 | 3 | 2 | 67% | 67% | 3 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-24 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-24 | 2 | 2 | 100% | 0% | 2 | 0 |