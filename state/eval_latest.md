# Watchtower Pipeline Eval — 2026-09-04T23:56:54Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 545 |
| After dedup + CVE merge | 530 |
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
| Risk score mean / p90 | 40 / 40 |
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
| `nvd` | 459 |
| `gcp_security` | 30 |
| `bsi_germany` | 20 |
| `bleepingcomputer` | 6 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-03 | 5 | ? | 0% | 0% | 4 | 0 |
| 2026-09-03 | 9 | ? | 0% | 0% | 8 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-04 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-04 | 11 | ? | 0% | 0% | 10 | 0 |