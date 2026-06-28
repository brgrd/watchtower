# Watchtower Pipeline Eval — 2026-06-28T22:10:18Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 20 |
| After dedup + CVE merge | 20 |
| Sent to Groq | 20 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/20 (15.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,741 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7404

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
- **Recommended actions**: 6 total — 100% specific, 0% generic

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
| `nvd` | 19 |
| `bleepingcomputer` | 1 |
| `cisa_alerts` | 0 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-27 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-27 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-28 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-06-28 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-06-28 | 3 | 3 | 100% | 0% | 3 | 0 |