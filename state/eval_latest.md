# Watchtower Pipeline Eval — 2026-05-31T11:45:48Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 74 |
| After dedup + CVE merge | 74 |
| Sent to Groq | 27 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/74 (2.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,590 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7619

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 84.5 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `msrc_update_guide` | 45 |
| `nvd` | 27 |
| `darkreading` | 2 |
| `cisa_kev` | 0 |
| `bleepingcomputer` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-29 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-29 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-30 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-05-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-31 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-31 | 3 | ? | 100% | 0% | 3 | 0 |