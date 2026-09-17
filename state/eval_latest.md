# Watchtower Pipeline Eval — 2026-09-17T11:32:22Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 325 |
| After dedup + CVE merge | 325 |
| Sent to Groq | 120 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/325 (4.6%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56 / 70 |
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
| EPSS | 1 | 7% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 232 |
| `nvd` | 81 |
| `bleepingcomputer` | 4 |
| `cisa_kev` | 3 |
| `securityweek` | 3 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-13 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-14 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-14 | 3 | ? | 0% | 0% | 2 | 0 |
| 2026-09-15 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-16 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-17 | 1 | ? | 0% | 0% | 0 | 0 |