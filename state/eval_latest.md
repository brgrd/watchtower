# Watchtower Pipeline Eval — 2026-09-24T22:16:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 747 |
| After dedup + CVE merge | 740 |
| Sent to Groq | 12 |
| Groq findings returned | 0 |
| Final cards rendered | 12 |
| **Pipeline yield** | **12/747 (1.6%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**12 cards** — P1: 0, P2: 0, P3: 12

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50.4 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 12 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **7** | Evolving (2–5): **5** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.6 | Mean shelf_days: 37.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 7 | 58% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 166 |
| `msrc_update_guide` | 17 |
| `securityweek` | 10 |
| `aws_security_bulletins` | 10 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-21 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-22 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-09-22 | 9 | ? | 0% | 0% | 8 | 0 |
| 2026-09-23 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-23 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-09-23 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-24 | 1 | ? | 0% | 0% | 0 | 0 |