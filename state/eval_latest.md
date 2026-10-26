# Watchtower Pipeline Eval — 2026-10-26T23:45:06Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 719 |
| After dedup + CVE merge | 712 |
| Sent to Groq | 3 |
| Groq findings returned | 0 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/719 (0.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**3 cards** — P1: 0, P2: 0, P3: 3

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56.7 / 60 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 3 | Mean shelf_days: 2.7

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
| `bsi_germany` | 143 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 8 |
| `msrc_update_guide` | 8 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-24 | 2 | ? | 0% | 0% | 0 | 0 |
| 2026-10-24 | 15 | ? | 0% | 0% | 13 | 0 |
| 2026-10-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-25 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-26 | 1 | ? | 0% | 0% | 0 | 0 |