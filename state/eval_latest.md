# Watchtower Pipeline Eval — 2026-06-03T23:54:53Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 161 |
| After dedup + CVE merge | 159 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/161 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,727 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7460

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 133 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 130 |
| `thehackernews` | 7 |
| `bleepingcomputer` | 6 |
| `securityweek` | 6 |
| `darkreading` | 6 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-06-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-03 | 2 | 1 | 100% | 50% | 2 | 0 |