# Watchtower Pipeline Eval — 2026-05-07T22:11:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 450 |
| After dedup + CVE merge | 446 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/450 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,630 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8211

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 67% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 106 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 8 total — 25% specific, 38% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 2 | 67% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 219 |
| `bsi_germany` | 170 |
| `bleepingcomputer` | 11 |
| `securityweek` | 10 |
| `thehackernews` | 9 |
| _(+19 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-03 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-03 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-04 | 3 | 1 | 67% | 0% | 3 | 0 |
| 2026-05-05 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-06 | 3 | 3 | 100% | 0% | 3 | 0 |