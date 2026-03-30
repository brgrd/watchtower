# Watchtower Pipeline Eval — 2026-03-30T22:50:36Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 334 |
| After dedup + CVE merge | 333 |
| Sent to Groq | 29 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/334 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,995 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10373

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 97 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 75% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 151 |
| `nvd` | 140 |
| `bleepingcomputer` | 10 |
| `securityweek` | 10 |
| `thehackernews` | 7 |
| _(+19 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-28 | 3 | 1 | 100% | 100% | 2 | 0 |
| 2026-03-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-03-29 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-29 | 2 | 2 | 100% | 0% | 2 | 0 |