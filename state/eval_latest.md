# Watchtower Pipeline Eval — 2026-10-20T00:13:22Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 829 |
| After dedup + CVE merge | 810 |
| Sent to Groq | 21 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/829 (1.8%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 51.7 / 60 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **14** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2.9 | Mean shelf_days: 91.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 14 | 93% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 233 |
| `aws_security_bulletins` | 44 |
| `bleepingcomputer` | 10 |
| `securityweek` | 9 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-16 | 3 | ? | 0% | 0% | 2 | 0 |
| 2026-10-16 | 9 | ? | 0% | 0% | 5 | 0 |
| 2026-10-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |