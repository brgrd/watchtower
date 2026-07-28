# Watchtower Pipeline Eval — 2026-07-28T22:12:46Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 350 |
| After dedup + CVE merge | 344 |
| Sent to Groq | 29 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/350 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,994 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6926

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 0% specific, 0% generic

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
| `nvd` | 195 |
| `bsi_germany` | 108 |
| `cisa_alerts` | 8 |
| `securityweek` | 7 |
| `bleepingcomputer` | 6 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-07-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-27 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-28 | 3 | 2 | 100% | 0% | 3 | 0 |