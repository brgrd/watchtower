# Watchtower Pipeline Eval — 2026-03-27T22:47:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 377 |
| After dedup + CVE merge | 377 |
| Sent to Groq | 29 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/377 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,998 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10459

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 51 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 50% generic

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
| `nvd` | 195 |
| `bsi_germany` | 147 |
| `securityweek` | 7 |
| `bleepingcomputer` | 6 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-23 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-03-24 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-03-24 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |