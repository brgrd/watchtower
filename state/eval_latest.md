# Watchtower Pipeline Eval — 2026-08-09T09:50:25Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 99 |
| After dedup + CVE merge | 99 |
| Sent to Groq | 99 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/99 (2.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,482 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6850

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 49 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 53 |
| `msrc_update_guide` | 46 |
| `bleepingcomputer` | 0 |
| `cisa_kev` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-07 | 5 | ? | 0% | 0% | 1 | 3 |
| 2026-08-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-08 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-08-08 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-08 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-08 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-08-08 | 3 | 3 | 100% | 0% | 3 | 0 |