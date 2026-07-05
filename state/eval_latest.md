# Watchtower Pipeline Eval — 2026-07-05T21:13:43Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 42 |
| After dedup + CVE merge | 42 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/42 (4.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,588 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7671

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 41 |
| `bleepingcomputer` | 1 |
| `cisa_alerts` | 0 |
| `krebs` | 0 |
| `cisa_kev` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-03 | 1 | 1 | 100% | 100% | 0 | 0 |
| 2026-07-03 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-04 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-04 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-04 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-04 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-05 | 3 | 3 | 100% | 0% | 3 | 0 |