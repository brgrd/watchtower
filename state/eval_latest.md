# Watchtower Pipeline Eval — 2026-06-04T12:10:46Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 95 |
| After dedup + CVE merge | 94 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/95 (3.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,804 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7318

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 33% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 63 |
| `msrc_update_guide` | 15 |
| `securityweek` | 5 |
| `thehackernews` | 4 |
| `darkreading` | 2 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-06-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-03 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 100% | 2 | 0 |