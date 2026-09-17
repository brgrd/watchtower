# Watchtower Pipeline Eval — 2026-09-17T23:30:09Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 768 |
| After dedup + CVE merge | 762 |
| Sent to Groq | 4 |
| Groq findings returned | 0 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/768 (0.5%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**4 cards** — P1: 0, P2: 0, P3: 4

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56.2 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.2 | Mean shelf_days: 0.2

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
| `msrc_update_guide` | 112 |
| `bsi_germany` | 110 |
| `cisa_alerts` | 8 |
| `securityweek` | 8 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-13 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-14 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-14 | 3 | ? | 0% | 0% | 2 | 0 |
| 2026-09-15 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-16 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-17 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-17 | 15 | ? | 0% | 0% | 15 | 0 |