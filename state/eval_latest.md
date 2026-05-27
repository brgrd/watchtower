# Watchtower Pipeline Eval — 2026-05-27T22:04:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 561 |
| After dedup + CVE merge | 557 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/561 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,888 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7195

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 54.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `nvd` | 500 |
| `bsi_germany` | 19 |
| `securityweek` | 9 |
| `thehackernews` | 6 |
| `darkreading` | 6 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-23 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-23 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-24 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-25 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-05-26 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-26 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-05-27 | 1 | 1 | 100% | 100% | 1 | 0 |