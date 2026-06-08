# Watchtower Pipeline Eval — 2026-06-08T11:17:37Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 223 |
| After dedup + CVE merge | 223 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/223 (1.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,592 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7675

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
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
| `bsi_germany` | 156 |
| `nvd` | 54 |
| `securityweek` | 5 |
| `bleepingcomputer` | 3 |
| `thehackernews` | 3 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-06 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-07 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 1 | 0 |