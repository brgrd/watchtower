# Watchtower Pipeline Eval — 2026-10-06T00:44:29Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 703 |
| After dedup + CVE merge | 698 |
| Sent to Groq | 3 |
| Groq findings returned | 0 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/703 (0.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**3 cards** — P1: 0, P2: 0, P3: 3

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 61.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 425 |
| `bsi_germany` | 236 |
| `bleepingcomputer` | 12 |
| `thehackernews` | 7 |
| `securityweek` | 7 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-01 | 10 | ? | 0% | 0% | 7 | 0 |
| 2026-10-02 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-02 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-10-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-03 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-10-04 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-10-04 | 1 | ? | 0% | 0% | 1 | 0 |