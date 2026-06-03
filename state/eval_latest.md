# Watchtower Pipeline Eval — 2026-06-03T11:19:55Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 332 |
| After dedup + CVE merge | 332 |
| Sent to Groq | 3 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/332 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,198 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7818

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 33 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 147 |
| `bsi_germany` | 126 |
| `nvd` | 41 |
| `bleepingcomputer` | 5 |
| `thehackernews` | 3 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-06-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 100% | 2 | 0 |