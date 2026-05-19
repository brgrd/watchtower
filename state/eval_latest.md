# Watchtower Pipeline Eval — 2026-05-19T12:50:30Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 353 |
| After dedup + CVE merge | 353 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/353 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,714 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7474

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 62 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `bsi_germany` | 168 |
| `msrc_update_guide` | 94 |
| `nvd` | 76 |
| `thehackernews` | 6 |
| `securityweek` | 5 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-17 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-17 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-17 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-18 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-18 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 3 | 100% | 0% | 3 | 0 |