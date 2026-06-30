# Watchtower Pipeline Eval — 2026-06-30T09:56:35Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 226 |
| After dedup + CVE merge | 226 |
| Sent to Groq | 29 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/226 (6.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,591 chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7663

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 44 / 40 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **15** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `bsi_germany` | 176 |
| `nvd` | 31 |
| `msrc_update_guide` | 6 |
| `thehackernews` | 4 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-28 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-28 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-29 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-29 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-29 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-30 | 3 | 1 | 100% | 33% | 3 | 0 |