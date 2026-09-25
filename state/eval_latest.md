# Watchtower Pipeline Eval — 2026-09-25T22:13:01Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 883 |
| After dedup + CVE merge | 867 |
| Sent to Groq | 9 |
| Groq findings returned | 0 |
| Final cards rendered | 9 |
| **Pipeline yield** | **9/883 (1.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**9 cards** — P1: 0, P2: 0, P3: 9

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60.6 / 80 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 9 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **6** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2.4 | Mean shelf_days: 46

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 5 | 56% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 182 |
| `msrc_update_guide` | 126 |
| `aws_security_bulletins` | 19 |
| `bleepingcomputer` | 11 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-22 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-09-22 | 9 | ? | 0% | 0% | 8 | 0 |
| 2026-09-23 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-23 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-09-23 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-24 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-24 | 12 | ? | 0% | 0% | 7 | 0 |