# Watchtower Pipeline Eval — 2026-06-30T12:19:47Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 308 |
| After dedup + CVE merge | 301 |
| Sent to Groq | 24 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/308 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,528 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6345

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 31.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 40% specific, 60% generic

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
| `bsi_germany` | 226 |
| `nvd` | 55 |
| `securityweek` | 8 |
| `thehackernews` | 6 |
| `msrc_update_guide` | 6 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-28 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-29 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-29 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-29 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-30 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-30 | 15 | ? | 0% | 0% | 15 | 0 |