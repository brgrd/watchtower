# Watchtower Pipeline Eval — 2026-11-25T22:24:10Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 598 |
| After dedup + CVE merge | 592 |
| Sent to Groq | 4 |
| Groq findings returned | 0 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/598 (0.7%)** |

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
| `nvd` | 333 |
| `bsi_germany` | 215 |
| `cisa_kev` | 10 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 5 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-19 | 6 | ? | 0% | 0% | 3 | 1 |
| 2026-11-20 | 8 | ? | 0% | 0% | 8 | 0 |
| 2026-11-21 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-11-21 | 4 | ? | 0% | 0% | 1 | 1 |
| 2026-11-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-23 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-25 | 15 | ? | 0% | 0% | 14 | 0 |