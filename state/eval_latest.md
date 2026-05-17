# Watchtower Pipeline Eval — 2026-05-17T11:20:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 30 |
| After dedup + CVE merge | 30 |
| Sent to Groq | 25 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/30 (10.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,908 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7090

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 62 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 0% specific, 50% generic

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
| `nvd` | 23 |
| `msrc_update_guide` | 5 |
| `thehackernews` | 1 |
| `darkreading` | 1 |
| `bleepingcomputer` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-16 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-17 | 3 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-17 | 3 | 3 | 100% | 0% | 3 | 0 |