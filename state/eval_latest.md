# Watchtower Pipeline Eval — 2026-04-21T10:25:39Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 136 |
| After dedup + CVE merge | 134 |
| Sent to Groq | 30 |
| Groq findings returned | 4 |
| Passed quality gate | 4 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/136 (2.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,757 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8490

## Card Quality

**4 cards** — P1: 4, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 62 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 8 total — 50% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `bsi_germany` | 64 |
| `nvd` | 57 |
| `cisa_kev` | 8 |
| `bleepingcomputer` | 4 |
| `thehackernews` | 1 |
| _(+19 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-17 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-17 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-04-19 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-04-19 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-04-20 | 3 | 3 | 100% | 0% | 3 | 0 |