# Watchtower Pipeline Eval — 2026-10-03T21:07:14Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 7 |
| After dedup + CVE merge | 7 |
| Sent to Groq | 7 |
| Groq findings returned | 0 |
| Final cards rendered | 7 |
| **Pipeline yield** | **7/7 (100.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**7 cards** — P1: 0, P2: 0, P3: 7

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 4.3 / 0 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 7 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **7** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `thehackernews` | 3 |
| `bleepingcomputer` | 2 |
| `securityweek` | 2 |
| `krebs` | 0 |
| `cisa_kev` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-28 | 5 | ? | 0% | 0% | 1 | 1 |
| 2026-09-30 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-09-30 | 3 | ? | 0% | 0% | 1 | 0 |
| 2026-10-01 | 10 | ? | 0% | 0% | 7 | 0 |
| 2026-10-02 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-02 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-10-03 | 15 | ? | 0% | 0% | 15 | 0 |