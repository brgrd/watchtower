# Watchtower Pipeline Eval — 2026-09-26T12:59:00Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 178 |
| After dedup + CVE merge | 176 |
| Sent to Groq | 1 |
| Groq findings returned | 0 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/178 (0.6%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**1 cards** — P1: 0, P2: 0, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 80 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 3 | Mean shelf_days: 4

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 162 |
| `thehackernews` | 3 |
| `cisa_kev` | 3 |
| `bleepingcomputer` | 2 |
| `github_changelog` | 2 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-22 | 9 | ? | 0% | 0% | 8 | 0 |
| 2026-09-23 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-23 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-09-23 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-24 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-24 | 12 | ? | 0% | 0% | 7 | 0 |
| 2026-09-25 | 9 | ? | 0% | 0% | 3 | 0 |