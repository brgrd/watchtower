# Watchtower Pipeline Eval — 2026-06-29T11:20:29Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 270 |
| After dedup + CVE merge | 270 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/270 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,812 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7287

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 98.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 7 total — 29% specific, 43% generic

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
| `bsi_germany` | 192 |
| `nvd` | 63 |
| `msrc_update_guide` | 7 |
| `securityweek` | 4 |
| `thehackernews` | 3 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-27 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-06-28 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-28 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-29 | ? | ? | ?% | ?% | ? | ? |