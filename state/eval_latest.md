# Watchtower Pipeline Eval — 2026-08-13T21:55:35Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 761 |
| After dedup + CVE merge | 759 |
| Sent to Groq | 7 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/761 (0.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 15,191 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6710

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 67% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 32 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 2 | 67% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 184 |
| `msrc_update_guide` | 28 |
| `cisa_alerts` | 14 |
| `bleepingcomputer` | 10 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-12 | 3 | 2 | 100% | 100% | 1 | 0 |
| 2026-08-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-12 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-08-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-12 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-08-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-13 | 3 | 3 | 100% | 0% | 3 | 0 |