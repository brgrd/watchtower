# Watchtower Pipeline Eval — 2026-06-24T00:05:35Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 75 |
| After dedup + CVE merge | 56 |
| Sent to Groq | 27 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/75 (20.0%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 27.7 / 45 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **10** | Evolving (2–5): **5** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 1.6

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 5 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `gcp_security` | 30 |
| `bleepingcomputer` | 9 |
| `github_changelog` | 5 |
| `securityweek` | 5 |
| `therecord` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-21 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 4 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-23 | 12 | ? | 0% | 0% | 12 | 0 |
| 2026-06-23 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-23 | 3 | 3 | 100% | 0% | 3 | 0 |