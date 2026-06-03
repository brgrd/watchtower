# Watchtower Pipeline Eval — 2026-06-03T21:26:49Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 191 |
| After dedup + CVE merge | 190 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/191 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,171 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6797

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 55 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 119.5 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 131 |
| `bsi_germany` | 23 |
| `thehackernews` | 8 |
| `securityweek` | 8 |
| `bleepingcomputer` | 7 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-01 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-06-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 0% | 2 | 0 |