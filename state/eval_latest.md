# Watchtower Pipeline Eval — 2026-04-04T22:41:53Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 41 |
| After dedup + CVE merge | 41 |
| Sent to Groq | 30 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/41 (2.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,750 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8512

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 104 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 50% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 22

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 36 |
| `bleepingcomputer` | 2 |
| `securityweek` | 1 |
| `darkreading` | 1 |
| `aws_security_blog` | 1 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-30 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-03-31 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-04-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-04 | 3 | 3 | 100% | 0% | 3 | 0 |