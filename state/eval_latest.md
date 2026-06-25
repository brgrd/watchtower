# Watchtower Pipeline Eval — 2026-06-25T22:39:53Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 374 |
| After dedup + CVE merge | 347 |
| Sent to Groq | 28 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/374 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,905 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7231

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 260 |
| `bsi_germany` | 31 |
| `gcp_security` | 30 |
| `cisa_alerts` | 10 |
| `bleepingcomputer` | 8 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-23 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 10 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-24 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-24 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 2 | 0 |