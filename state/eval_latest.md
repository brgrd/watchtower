# Watchtower Pipeline Eval — 2026-08-21T10:38:52Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 215 |
| After dedup + CVE merge | 211 |
| Sent to Groq | 30 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/215 (7.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 54 / 70 |
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
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 133 |
| `nvd` | 71 |
| `securityweek` | 4 |
| `thehackernews` | 2 |
| `cisa_kev` | 2 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-20 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 4 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 5 | 0 |
| 2026-08-21 | 15 | ? | 0% | 0% | 15 | 0 |