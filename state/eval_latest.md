# Watchtower Pipeline Eval — 2026-06-26T00:19:31Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 69 |
| After dedup + CVE merge | 44 |
| Sent to Groq | 28 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/69 (21.7%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 7.3 / 20 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **14** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 1.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 13% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `gcp_security` | 30 |
| `bleepingcomputer` | 8 |
| `github_changelog` | 8 |
| `cyberscoop` | 4 |
| `darkreading` | 4 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-24 | 15 | ? | 0% | 0% | 10 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-24 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-24 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 2 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 3 | 0 |