# Watchtower Pipeline Eval — 2026-04-05T22:45:07Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 87 |
| After dedup + CVE merge | 87 |
| Sent to Groq | 30 |
| Groq findings returned | 4 |
| Passed quality gate | 4 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/87 (4.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,196 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8389

## Card Quality

**4 cards** — P1: 4, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 47.5 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 56 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 8 total — 50% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 75% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 82 |
| `bleepingcomputer` | 3 |
| `thehackernews` | 1 |
| `darkreading` | 1 |
| `cisa_alerts` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 1 | 1 | 100% | 0% | 0 | 0 |
| 2026-04-05 | 3 | 3 | 100% | 0% | 3 | 0 |