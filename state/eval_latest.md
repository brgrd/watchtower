# Watchtower Pipeline Eval — 2026-04-06T22:50:24Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 346 |
| After dedup + CVE merge | 343 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/346 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,203 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8399

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 70 |
| Tactic coverage | 67% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 67 chars (100% ≥ 60 chars, considered substantive)
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
| `nvd` | 305 |
| `bleepingcomputer` | 8 |
| `thehackernews` | 7 |
| `darkreading` | 7 |
| `therecord` | 5 |
| _(+19 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 1 | 1 | 100% | 0% | 0 | 0 |
| 2026-04-05 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-05 | 4 | 4 | 100% | 0% | 4 | 0 |