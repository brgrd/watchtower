# Watchtower Pipeline Eval — 2026-11-28T01:52:25Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 601 |
| After dedup + CVE merge | 599 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/601 (0.3%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 55 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 1.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 362 |
| `bsi_germany` | 207 |
| `bleepingcomputer` | 11 |
| `thehackernews` | 6 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-21 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-11-21 | 4 | ? | 0% | 0% | 1 | 1 |
| 2026-11-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-23 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-25 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-11-25 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-11-26 | 3 | ? | 0% | 0% | 3 | 0 |