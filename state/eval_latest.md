# Watchtower Pipeline Eval — 2026-10-15T22:08:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 967 |
| After dedup + CVE merge | 958 |
| Sent to Groq | 11 |
| Groq findings returned | 0 |
| Final cards rendered | 11 |
| **Pipeline yield** | **11/967 (1.1%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**11 cards** — P1: 0, P2: 0, P3: 11

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 62.7 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 11 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **7** | Evolving (2–5): **4** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 1.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 235 |
| `msrc_update_guide` | 156 |
| `thehackernews` | 15 |
| `bleepingcomputer` | 10 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-10 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-11 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-12 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-13 | 5 | ? | 0% | 0% | 1 | 1 |
| 2026-10-13 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-10-14 | 15 | ? | 0% | 0% | 5 | 0 |