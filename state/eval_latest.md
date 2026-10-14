# Watchtower Pipeline Eval — 2026-10-14T22:12:21Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 918 |
| After dedup + CVE merge | 901 |
| Sent to Groq | 28 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/918 (1.6%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 57 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **5** | Evolving (2–5): **10** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2.3 | Mean shelf_days: 66.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 10 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 250 |
| `aws_security_bulletins` | 44 |
| `gcp_security` | 30 |
| `msrc_update_guide` | 20 |
| _(+21 more)_ | … |

**5 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-09 | 13 | ? | 0% | 0% | 7 | 0 |
| 2026-10-10 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-12 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-13 | 5 | ? | 0% | 0% | 1 | 1 |
| 2026-10-13 | 4 | ? | 0% | 0% | 4 | 0 |