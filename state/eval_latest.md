# Watchtower Pipeline Eval — 2026-06-05T12:17:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 715 |
| After dedup + CVE merge | 713 |
| Sent to Groq | 24 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/715 (0.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,823 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7362

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 30.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 498 |
| `bsi_germany` | 200 |
| `securityweek` | 6 |
| `msrc_update_guide` | 6 |
| `thehackernews` | 3 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-02 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-03 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-04 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-06-04 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-04 | 3 | 1 | 100% | 0% | 3 | 0 |