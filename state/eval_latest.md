# Watchtower Pipeline Eval — 2026-05-29T22:00:27Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 265 |
| After dedup + CVE merge | 264 |
| Sent to Groq | 26 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/265 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,955 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7104

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 52 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 218 |
| `bsi_germany` | 13 |
| `bleepingcomputer` | 7 |
| `securityweek` | 6 |
| `darkreading` | 6 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-27 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-27 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-28 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-05-28 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-29 | 3 | 1 | 67% | 100% | 3 | 0 |