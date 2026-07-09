# Watchtower Pipeline Eval — 2026-07-09T22:40:01Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 249 |
| After dedup + CVE merge | 247 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/249 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,601 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7673

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

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
| `nvd` | 203 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 7 |
| `bsi_germany` | 6 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-07 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-08 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-09 | 2 | 1 | 100% | 0% | 2 | 0 |