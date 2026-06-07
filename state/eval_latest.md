# Watchtower Pipeline Eval — 2026-06-07T22:13:33Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 7 |
| After dedup + CVE merge | 7 |
| Sent to Groq | 7 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/7 (42.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,646 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7145

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 32.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 3 |
| `bleepingcomputer` | 2 |
| `securityweek` | 1 |
| `darkreading` | 1 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-06 | 15 | ? | 0% | 0% | 11 | 0 |
| 2026-06-06 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-06 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-06 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-07 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-07 | 3 | 2 | 100% | 0% | 3 | 0 |