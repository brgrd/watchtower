# Watchtower Pipeline Eval — 2026-11-08T23:37:39Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 322 |
| After dedup + CVE merge | 322 |
| Sent to Groq | 120 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/322 (4.7%)** |

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
| EPSS | 4 | 27% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 320 |
| `bleepingcomputer` | 1 |
| `securityweek` | 1 |
| `krebs` | 0 |
| `thehackernews` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-02 | 6 | ? | 0% | 0% | 4 | 0 |
| 2026-11-04 | 11 | ? | 0% | 0% | 8 | 1 |
| 2026-11-04 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-11-05 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-11-06 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-11-06 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-11-08 | 1 | ? | 0% | 0% | 0 | 0 |