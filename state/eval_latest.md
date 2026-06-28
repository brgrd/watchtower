# Watchtower Pipeline Eval — 2026-06-28T09:26:31Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 476 |
| After dedup + CVE merge | 476 |
| Sent to Groq | 120 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/476 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,275 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7483

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56.7 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 67% specific, 33% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 458 |
| `nvd` | 18 |
| `bleepingcomputer` | 0 |
| `krebs` | 0 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-26 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-26 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-27 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-27 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 1 | ? | 0% | 0% | 1 | 0 |