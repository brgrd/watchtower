# Watchtower Pipeline Eval — 2026-09-04T21:22:16Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 799 |
| After dedup + CVE merge | 788 |
| Sent to Groq | 11 |
| Groq findings returned | 0 |
| Final cards rendered | 11 |
| **Pipeline yield** | **11/799 (1.4%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**11 cards** — P1: 0, P2: 0, P3: 11

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 52.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 11 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **10** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 0.2

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 9% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 479 |
| `bsi_germany` | 250 |
| `gcp_security` | 30 |
| `securityweek` | 9 |
| `bleepingcomputer` | 7 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-03 | 5 | ? | 0% | 0% | 4 | 0 |
| 2026-09-03 | 9 | ? | 0% | 0% | 8 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-04 | 1 | ? | 0% | 0% | 1 | 0 |