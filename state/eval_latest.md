# Watchtower Pipeline Eval — 2026-06-21T00:17:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 2 |
| After dedup + CVE merge | 2 |
| Sent to Groq | 2 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/2 (100.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,814 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7756

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 54.5 chars (0% ≥ 60 chars, considered substantive)
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
| `bleepingcomputer` | 2 |
| `nvd` | 0 |
| `cisa_alerts` | 0 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-18 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-19 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-19 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-20 | 2 | 1 | 100% | 0% | 2 | 0 |