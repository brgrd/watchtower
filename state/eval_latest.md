# Watchtower Pipeline Eval — 2026-08-15T23:28:14Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 178 |
| After dedup + CVE merge | 178 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/178 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,604 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7667

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 56.5 chars (50% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

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
| `nvd` | 177 |
| `bleepingcomputer` | 1 |
| `cisa_alerts` | 0 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-14 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-15 | 3 | ? | 100% | 0% | 2 | 0 |
| 2026-08-15 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-15 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-15 | ? | ? | ?% | ?% | ? | ? |
| 2026-08-15 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-15 | 3 | ? | 100% | 0% | 3 | 0 |