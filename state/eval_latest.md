# Watchtower Pipeline Eval — 2026-07-21T11:54:49Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 353 |
| After dedup + CVE merge | 352 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/353 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,044 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7029

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 0% specific, 50% generic

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
| `bsi_germany` | 239 |
| `msrc_update_guide` | 60 |
| `nvd` | 40 |
| `securityweek` | 6 |
| `bleepingcomputer` | 4 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-19 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | ? | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | ? | 100% | 0% | 1 | 0 |
| 2026-07-21 | 3 | 3 | 100% | 0% | 3 | 0 |