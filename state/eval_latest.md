# Watchtower Pipeline Eval — 2026-07-17T12:17:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 269 |
| After dedup + CVE merge | 268 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/269 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,587 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7671

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 111 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 50% generic

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
| `bsi_germany` | 152 |
| `nvd` | 84 |
| `msrc_update_guide` | 15 |
| `securityweek` | 7 |
| `thehackernews` | 6 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-15 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-15 | 3 | 2 | 100% | 0% | 2 | 0 |
| 2026-07-16 | 3 | 2 | 100% | 33% | 1 | 0 |
| 2026-07-16 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-16 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-17 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-07-17 | 2 | 2 | 100% | 100% | 2 | 0 |