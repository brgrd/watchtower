# Watchtower Pipeline Eval — 2026-11-19T12:50:22Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 810 |
| After dedup + CVE merge | 799 |
| Sent to Groq | 6 |
| Groq findings returned | 0 |
| Final cards rendered | 6 |
| **Pipeline yield** | **6/810 (0.7%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**6 cards** — P1: 0, P2: 0, P3: 6

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 6 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **2** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 2.7 | Mean shelf_days: 9.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 216 |
| `gcp_security` | 30 |
| `thehackernews` | 13 |
| `securityweek` | 10 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-14 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-15 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-11-16 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-17 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-17 | 9 | ? | 0% | 0% | 4 | 2 |
| 2026-11-18 | 15 | ? | 0% | 0% | 15 | 0 |