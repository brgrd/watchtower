# Watchtower Pipeline Eval — 2026-11-01T23:29:31Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 107 |
| After dedup + CVE merge | 107 |
| Sent to Groq | 107 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/107 (14.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 74 / 90 |
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
| EPSS | 11 | 73% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 98 |
| `thehackernews` | 4 |
| `bleepingcomputer` | 3 |
| `securityweek` | 1 |
| `cyberscoop` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-27 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-10-29 | 8 | ? | 0% | 0% | 7 | 0 |
| 2026-10-30 | 6 | ? | 0% | 0% | 3 | 0 |
| 2026-10-30 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-10-31 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-10-31 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-11-01 | 15 | ? | 0% | 0% | 15 | 0 |