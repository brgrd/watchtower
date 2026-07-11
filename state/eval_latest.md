# Watchtower Pipeline Eval — 2026-07-11T10:22:00Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 165 |
| After dedup + CVE merge | 165 |
| Sent to Groq | 2 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/165 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,978 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8141

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
| `nvd` | 126 |
| `msrc_update_guide` | 33 |
| `bleepingcomputer` | 2 |
| `cisa_kev` | 2 |
| `thehackernews` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-09 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-09 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-10 | 3 | ? | 100% | 0% | 3 | 0 |