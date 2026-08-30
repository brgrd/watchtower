# Watchtower Pipeline Eval — 2026-08-30T23:24:23Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 79 |
| After dedup + CVE merge | 77 |
| Sent to Groq | 77 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/79 (19.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **15** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 74 |
| `bleepingcomputer` | 3 |
| `darkreading` | 2 |
| `gh_security_blog` | 0 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-26 | 12 | ? | 0% | 0% | 12 | 0 |
| 2026-08-26 | 8 | ? | 0% | 0% | 3 | 3 |
| 2026-08-27 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-08-29 | 10 | ? | 0% | 0% | 10 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |