# Watchtower Pipeline Eval — 2026-07-19T00:01:41Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 66 |
| After dedup + CVE merge | 66 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/66 (3.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,589 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7655

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 67.5 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 71 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 0.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 62 |
| `bleepingcomputer` | 4 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-17 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-18 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-18 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-18 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-18 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-18 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-18 | 2 | 1 | 100% | 0% | 2 | 0 |