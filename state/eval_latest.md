# Watchtower Pipeline Eval — 2026-05-29T23:23:37Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 242 |
| After dedup + CVE merge | 241 |
| Sent to Groq | 26 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/242 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,952 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7110

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
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
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 212 |
| `darkreading` | 6 |
| `bleepingcomputer` | 5 |
| `securityweek` | 4 |
| `msrc_update_guide` | 4 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-27 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-28 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-05-28 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-28 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-29 | 3 | 1 | 67% | 100% | 3 | 0 |
| 2026-05-29 | 3 | 2 | 100% | 0% | 3 | 0 |