# Watchtower Pipeline Eval — 2026-07-27T11:34:27Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 226 |
| After dedup + CVE merge | 226 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/226 (1.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,588 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7678

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 47 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 40% specific, 60% generic

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
| `nvd` | 44 |
| `securityweek` | 7 |
| `msrc_update_guide` | 5 |
| `thehackernews` | 2 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-25 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-25 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-25 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 2 | ? | 100% | 0% | 2 | 0 |