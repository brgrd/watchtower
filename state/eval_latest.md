# Watchtower Pipeline Eval — 2026-06-14T09:52:24Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 6 |
| After dedup + CVE merge | 6 |
| Sent to Groq | 6 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/6 (50.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,622 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7747

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 92 chars (100% ≥ 60 chars, considered substantive)
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
| `nvd` | 5 |
| `darkreading` | 1 |
| `bleepingcomputer` | 0 |
| `cisa_alerts` | 0 |
| `gh_security_blog` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-11 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-12 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-12 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-06-12 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-06-13 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-13 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-14 | 5 | 1 | 100% | 20% | 3 | 0 |