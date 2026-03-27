# Watchtower Pipeline Eval — 2026-03-27T10:03:30Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 267 |
| After dedup + CVE merge | 267 |
| Sent to Groq | 29 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/267 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,994 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10447

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 123.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 75% generic

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
| `bsi_germany` | 133 |
| `nvd` | 125 |
| `bleepingcomputer` | 2 |
| `unit42` | 2 |
| `cisa_kev` | 1 |
| _(+19 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-22 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-23 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-03-24 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-03-24 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-26 | 3 | 1 | 100% | 0% | 3 | 0 |