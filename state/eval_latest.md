# Watchtower Pipeline Eval — 2026-06-26T21:37:37Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 383 |
| After dedup + CVE merge | 382 |
| Sent to Groq | 16 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/383 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,265 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6691

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 24 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 33% specific, 67% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 298 |
| `bsi_germany` | 36 |
| `msrc_update_guide` | 14 |
| `thehackernews` | 9 |
| `securityweek` | 6 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-24 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 2 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-26 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-26 | 3 | ? | 100% | 0% | 3 | 0 |