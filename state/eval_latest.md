# Watchtower Pipeline Eval — 2026-07-15T09:17:33Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 287 |
| After dedup + CVE merge | 283 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/287 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,724 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7419

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

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
| `bsi_germany` | 167 |
| `nvd` | 77 |
| `msrc_update_guide` | 27 |
| `cisa_kev` | 4 |
| `bleepingcomputer` | 3 |
| _(+21 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-13 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-07-14 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-14 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-14 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-07-14 | 3 | 1 | 100% | 100% | 1 | 0 |