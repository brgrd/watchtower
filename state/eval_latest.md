# Watchtower Pipeline Eval — 2026-05-11T12:19:32Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 640 |
| After dedup + CVE merge | 628 |
| Sent to Groq | 2 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/640 (0.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,917 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7885

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 64.5 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 359 |
| `nvd` | 152 |
| `bsi_germany` | 113 |
| `securityweek` | 8 |
| `bleepingcomputer` | 3 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-08 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-09 | 2 | 1 | 100% | 0% | 1 | 0 |