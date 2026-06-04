# Watchtower Pipeline Eval — 2026-06-04T21:50:03Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 191 |
| After dedup + CVE merge | 190 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/191 (1.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,879 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7154

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 51.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 60% specific, 40% generic

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
| `nvd` | 136 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 7 |
| `securityweek` | 7 |
| `github_changelog` | 6 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-03 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-06-03 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-04 | 3 | 2 | 100% | 33% | 3 | 0 |