# Watchtower Pipeline Eval — 2026-09-10T00:05:21Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 353 |
| After dedup + CVE merge | 327 |
| Sent to Groq | 11 |
| Groq findings returned | 0 |
| Final cards rendered | 11 |
| **Pipeline yield** | **11/353 (3.1%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**11 cards** — P1: 0, P2: 0, P3: 11

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 43.6 / 45 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 11 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **7** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 15.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 11 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 252 |
| `aws_security_bulletins` | 34 |
| `bsi_germany` | 13 |
| `msrc_update_guide` | 9 |
| `bleepingcomputer` | 6 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-07 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-07 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-08 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-08 | 6 | ? | 0% | 0% | 3 | 1 |
| 2026-09-09 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-09 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-09-09 | 15 | ? | 0% | 0% | 3 | 0 |