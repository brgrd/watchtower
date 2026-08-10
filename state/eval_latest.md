# Watchtower Pipeline Eval — 2026-08-10T23:45:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 690 |
| After dedup + CVE merge | 690 |
| Sent to Groq | 21 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/690 (0.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,608 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7690

## Card Quality

**2 cards** — P1: 0, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 48.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 0% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 500 |
| `bsi_germany` | 134 |
| `bleepingcomputer` | 9 |
| `msrc_update_guide` | 9 |
| `darkreading` | 7 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-09 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-09 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-09 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |