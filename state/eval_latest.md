# Watchtower Pipeline Eval — 2026-05-05T22:09:12Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 333 |
| After dedup + CVE merge | 332 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/333 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,535 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7917

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

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
| `nvd` | 200 |
| `bsi_germany` | 86 |
| `bleepingcomputer` | 12 |
| `thehackernews` | 9 |
| `securityweek` | 8 |
| _(+19 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-30 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-05-01 | 2 | 2 | 100% | 0% | 0 | 0 |
| 2026-05-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-03 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-03 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-04 | 3 | 1 | 67% | 0% | 3 | 0 |