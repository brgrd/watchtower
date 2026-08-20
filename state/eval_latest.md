# Watchtower Pipeline Eval — 2026-08-20T23:33:53Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 599 |
| After dedup + CVE merge | 549 |
| Sent to Groq | 30 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/599 (2.5%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 45.3 / 50 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **5** | Evolving (2–5): **10** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.8 | Mean shelf_days: 44.9

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 14 | 93% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 432 |
| `aws_security_bulletins` | 85 |
| `msrc_update_guide` | 36 |
| `thehackernews` | 11 |
| `darkreading` | 7 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-20 | 15 | ? | 0% | 0% | 4 | 0 |