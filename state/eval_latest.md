# Watchtower Pipeline Eval — 2026-09-21T23:11:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 545 |
| After dedup + CVE merge | 543 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/545 (0.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 294 |
| `bsi_germany` | 191 |
| `msrc_update_guide` | 14 |
| `securityweek` | 10 |
| `bleepingcomputer` | 9 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-19 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-19 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-20 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-21 | 15 | ? | 0% | 0% | 15 | 0 |