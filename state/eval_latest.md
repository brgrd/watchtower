# Watchtower Pipeline Eval — 2026-09-07T23:26:01Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 275 |
| After dedup + CVE merge | 273 |
| Sent to Groq | 120 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/275 (5.5%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
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
| EPSS | 5 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 188 |
| `bsi_germany` | 65 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 7 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-05 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-05 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-09-05 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-07 | 15 | ? | 0% | 0% | 15 | 0 |