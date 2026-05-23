# Watchtower Pipeline Eval — 2026-05-23T09:08:26Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 434 |
| After dedup + CVE merge | 429 |
| Sent to Groq | 7 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/434 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,664 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6555

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 46 chars (33% ≥ 60 chars, considered substantive)
- **Recommended actions**: 9 total — 33% specific, 33% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 233 |
| `bsi_germany` | 152 |
| `thehackernews` | 9 |
| `bleepingcomputer` | 7 |
| `securityweek` | 6 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-19 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-20 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-21 | 2 | 1 | 100% | 100% | 2 | 0 |