# Watchtower Pipeline Eval — 2026-08-11T11:51:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 543 |
| After dedup + CVE merge | 543 |
| Sent to Groq | 120 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/543 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,436 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6925

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `msrc_update_guide` | 314 |
| `bsi_germany` | 130 |
| `nvd` | 87 |
| `thehackernews` | 5 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-10 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-08-11 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-11 | 3 | 3 | 100% | 0% | 3 | 0 |