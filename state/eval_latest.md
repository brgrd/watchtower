# Watchtower Pipeline Eval — 2026-10-16T23:28:03Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 727 |
| After dedup + CVE merge | 716 |
| Sent to Groq | 9 |
| Groq findings returned | 0 |
| Final cards rendered | 9 |
| **Pipeline yield** | **9/727 (1.2%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**9 cards** — P1: 0, P2: 0, P3: 9

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 9 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **5** | Evolving (2–5): **4** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 33.8

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 5 | 56% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 294 |
| `nvd` | 288 |
| `bsi_germany` | 100 |
| `aws_security_bulletins` | 9 |
| `darkreading` | 7 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-12 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-13 | 5 | ? | 0% | 0% | 1 | 1 |
| 2026-10-13 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-10-14 | 15 | ? | 0% | 0% | 5 | 0 |
| 2026-10-15 | 11 | ? | 0% | 0% | 7 | 0 |
| 2026-10-16 | 3 | ? | 0% | 0% | 2 | 0 |