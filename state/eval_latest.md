# Watchtower Pipeline Eval — 2026-10-23T22:03:44Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 665 |
| After dedup + CVE merge | 658 |
| Sent to Groq | 14 |
| Groq findings returned | 0 |
| Final cards rendered | 14 |
| **Pipeline yield** | **14/665 (2.1%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**14 cards** — P1: 0, P2: 0, P3: 14

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 48.9 / 60 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 14 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **8** | Evolving (2–5): **6** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.9 | Mean shelf_days: 18.1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 6 | 43% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 431 |
| `bsi_germany` | 152 |
| `gcp_security` | 30 |
| `thehackernews` | 9 |
| `bleepingcomputer` | 7 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-20 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-10-20 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-10-21 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-10-21 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-22 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-22 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-10-23 | 2 | ? | 0% | 0% | 1 | 0 |