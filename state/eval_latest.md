# Watchtower Pipeline Eval — 2026-06-06T10:15:10Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 55 |
| After dedup + CVE merge | 54 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/55 (5.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,599 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7696

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 26 chars (0% ≥ 60 chars, considered substantive)
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
| `nvd` | 46 |
| `thehackernews` | 5 |
| `cisa_kev` | 1 |
| `github_changelog` | 1 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-03 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-04 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-06-04 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-04 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-05 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-05 | 15 | ? | 0% | 0% | 13 | 0 |
| 2026-06-06 | 15 | ? | 0% | 0% | 11 | 0 |