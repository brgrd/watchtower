# Watchtower Pipeline Eval — 2026-04-03T10:57:15Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 52 |
| After dedup + CVE merge | 52 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/52 (5.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,749 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8494

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 87 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 0% generic

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
| `nvd` | 39 |
| `bleepingcomputer` | 3 |
| `securityweek` | 3 |
| `thehackernews` | 2 |
| `darkreading` | 2 |
| _(+19 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-03-29 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-29 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-03-30 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-03-31 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-04-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-02 | 3 | 2 | 100% | 0% | 3 | 0 |