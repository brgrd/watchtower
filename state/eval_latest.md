# Watchtower Pipeline Eval — 2026-10-27T21:13:03Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 711 |
| After dedup + CVE merge | 706 |
| Sent to Groq | 6 |
| Groq findings returned | 0 |
| Final cards rendered | 6 |
| **Pipeline yield** | **6/711 (0.8%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**6 cards** — P1: 0, P2: 0, P3: 6

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 61.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 6 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **5** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 4.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 489 |
| `bsi_germany` | 167 |
| `msrc_update_guide` | 9 |
| `thehackernews` | 8 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-25 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 3 | ? | 0% | 0% | 1 | 0 |
| 2026-10-27 | 1 | ? | 0% | 0% | 0 | 1 |