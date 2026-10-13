# Watchtower Pipeline Eval — 2026-10-13T22:36:39Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 1711 |
| After dedup + CVE merge | 1706 |
| Sent to Groq | 4 |
| Groq findings returned | 0 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/1711 (0.2%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**4 cards** — P1: 0, P2: 0, P3: 4

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 55 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `msrc_update_guide` | 1412 |
| `bsi_germany` | 235 |
| `bleepingcomputer` | 13 |
| `thehackernews` | 12 |
| `securityweek` | 10 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-08 | 5 | ? | 0% | 0% | 4 | 0 |
| 2026-10-09 | 13 | ? | 0% | 0% | 7 | 0 |
| 2026-10-10 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-12 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-13 | 5 | ? | 0% | 0% | 1 | 1 |