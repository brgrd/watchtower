# Watchtower Pipeline Eval — 2026-03-20T10:52:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 407 |
| After dedup + CVE merge | 406 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/407 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,000 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10447

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 97 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 0.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 287 |
| `bsi_germany` | 103 |
| `bleepingcomputer` | 4 |
| `securityweek` | 4 |
| `thehackernews` | 3 |
| _(+19 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-18 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-03-18 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-03-18 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-03-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-19 | 3 | 1 | 100% | 0% | 3 | 0 |