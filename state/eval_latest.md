# Watchtower Pipeline Eval — 2026-07-25T09:06:59Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 23 |
| After dedup + CVE merge | 23 |
| Sent to Groq | 19 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/23 (65.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,055 chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6902

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 44.3 / 45 |
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
| `nvd` | 16 |
| `msrc_update_guide` | 4 |
| `thehackernews` | 1 |
| `securityweek` | 1 |
| `darkreading` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-23 | 3 | 2 | 67% | 67% | 3 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-24 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-24 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-07-24 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-24 | 2 | 1 | 100% | 0% | 2 | 0 |