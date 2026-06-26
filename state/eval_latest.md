# Watchtower Pipeline Eval — 2026-06-26T09:47:01Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 231 |
| After dedup + CVE merge | 227 |
| Sent to Groq | 22 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/231 (6.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,748 chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7447

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 57.3 / 70 |
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
| `bsi_germany` | 124 |
| `nvd` | 86 |
| `msrc_update_guide` | 8 |
| `securityweek` | 4 |
| `bleepingcomputer` | 2 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-24 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-24 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 2 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-26 | 15 | ? | 0% | 0% | 14 | 0 |