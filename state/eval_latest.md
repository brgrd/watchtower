# Watchtower Pipeline Eval — 2026-08-03T21:14:37Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 292 |
| After dedup + CVE merge | 287 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/292 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,124 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6746

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 29.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 134 |
| `nvd` | 115 |
| `securityweek` | 9 |
| `thehackernews` | 6 |
| `bleepingcomputer` | 5 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-02 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-02 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-03 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-08-03 | 3 | ? | 100% | 0% | 3 | 0 |