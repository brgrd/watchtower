# Watchtower Pipeline Eval — 2026-06-08T23:19:38Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 211 |
| After dedup + CVE merge | 206 |
| Sent to Groq | 28 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/211 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,102 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6846

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
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
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 166 |
| `bleepingcomputer` | 9 |
| `thehackernews` | 6 |
| `securityweek` | 6 |
| `darkreading` | 5 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-07 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 1 | 0 |
| 2026-06-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-08 | 3 | 2 | 100% | 100% | 3 | 0 |