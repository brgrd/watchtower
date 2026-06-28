# Watchtower Pipeline Eval — 2026-06-28T00:11:21Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 4 |
| After dedup + CVE merge | 1 |
| Sent to Groq | 1 |
| Groq findings returned | 0 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/4 (25.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,711 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7918

## Card Quality

**1 cards** — P1: 0, P2: 0, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 0 / 0 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `thehackernews` | 2 |
| `bleepingcomputer` | 1 |
| `securityweek` | 1 |
| `nvd` | 0 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-26 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-26 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-27 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-27 | 3 | 2 | 100% | 0% | 3 | 0 |