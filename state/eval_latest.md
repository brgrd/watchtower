# Watchtower Pipeline Eval — 2026-05-21T12:24:30Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 266 |
| After dedup + CVE merge | 263 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/266 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,637 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6494

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 41 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 3 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 138 |
| `nvd` | 73 |
| `msrc_update_guide` | 25 |
| `securityweek` | 8 |
| `cisa_kev` | 7 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-05-19 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-20 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | 2 | 100% | 0% | 3 | 0 |