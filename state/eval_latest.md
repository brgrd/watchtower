# Watchtower Pipeline Eval — 2026-06-05T22:24:33Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 247 |
| After dedup + CVE merge | 241 |
| Sent to Groq | 30 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/247 (6.1%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50.3 / 60 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **13** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.2 | Mean shelf_days: 2.1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 9 | 60% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 136 |
| `aws_security_bulletins` | 58 |
| `bsi_germany` | 22 |
| `bleepingcomputer` | 6 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-03 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-03 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-04 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-06-04 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-04 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-05 | 3 | 1 | 100% | 0% | 3 | 0 |