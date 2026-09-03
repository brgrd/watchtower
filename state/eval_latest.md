# Watchtower Pipeline Eval — 2026-09-03T23:58:07Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 432 |
| After dedup + CVE merge | 414 |
| Sent to Groq | 120 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/432 (3.5%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **15** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 13 | 87% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 345 |
| `msrc_update_guide` | 35 |
| `cisa_alerts` | 11 |
| `bleepingcomputer` | 9 |
| `github_changelog` | 7 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-01 | 9 | ? | 0% | 0% | 9 | 0 |
| 2026-09-02 | 2 | ? | 0% | 0% | 0 | 0 |
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-03 | 5 | ? | 0% | 0% | 4 | 0 |
| 2026-09-03 | 9 | ? | 0% | 0% | 8 | 0 |