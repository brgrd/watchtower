# Watchtower Pipeline Eval — 2026-09-22T09:50:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 107 |
| After dedup + CVE merge | 105 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/107 (1.9%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 57.5 / 40 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 0.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 91 |
| `bsi_germany` | 5 |
| `thehackernews` | 4 |
| `securityweek` | 2 |
| `bleepingcomputer` | 1 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-19 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-19 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-20 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-21 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-21 | 2 | ? | 0% | 0% | 2 | 0 |