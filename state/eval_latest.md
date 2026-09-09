# Watchtower Pipeline Eval — 2026-09-09T21:38:22Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 464 |
| After dedup + CVE merge | 448 |
| Sent to Groq | 25 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/464 (3.2%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50.3 / 65 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **12** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.9 | Mean shelf_days: 17.1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 13 | 87% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 279 |
| `bsi_germany` | 87 |
| `aws_security_bulletins` | 34 |
| `securityweek` | 10 |
| `thehackernews` | 9 |
| _(+21 more)_ | … |

**7 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-07 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-07 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-08 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-08 | 6 | ? | 0% | 0% | 3 | 1 |
| 2026-09-09 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-09 | 4 | ? | 0% | 0% | 4 | 0 |