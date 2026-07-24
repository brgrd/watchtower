# Watchtower Pipeline Eval — 2026-07-24T11:50:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 236 |
| After dedup + CVE merge | 236 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/236 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,587 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7718

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 58 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 0% specific, 50% generic

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
| `bsi_germany` | 163 |
| `nvd` | 59 |
| `thehackernews` | 6 |
| `msrc_update_guide` | 3 |
| `bleepingcomputer` | 2 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-22 | 15 | ? | 0% | 0% | 6 | 1 |
| 2026-07-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-23 | 3 | 2 | 67% | 67% | 3 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-07-24 | 3 | 3 | 100% | 0% | 3 | 0 |