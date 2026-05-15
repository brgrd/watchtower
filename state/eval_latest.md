# Watchtower Pipeline Eval — 2026-05-15T22:07:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 177 |
| After dedup + CVE merge | 174 |
| Sent to Groq | 26 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/177 (1.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,885 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7163

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
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
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 125 |
| `bsi_germany` | 19 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 4 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-13 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 0% | 3 | 0 |