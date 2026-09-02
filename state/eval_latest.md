# Watchtower Pipeline Eval — 2026-09-02T00:00:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 426 |
| After dedup + CVE merge | 422 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/426 (0.5%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 386 |
| `bleepingcomputer` | 7 |
| `darkreading` | 7 |
| `github_changelog` | 6 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-29 | 10 | ? | 0% | 0% | 10 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-31 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 9 | ? | 0% | 0% | 9 | 0 |