# Watchtower Pipeline Eval — 2026-10-27T10:23:37Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 136 |
| After dedup + CVE merge | 135 |
| Sent to Groq | 1 |
| Groq findings returned | 0 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/136 (0.7%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**1 cards** — P1: 0, P2: 0, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 90 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **0** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 6 | Mean shelf_days: 6

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 117 |
| `thehackernews` | 4 |
| `securityweek` | 4 |
| `bleepingcomputer` | 2 |
| `cisa_kev` | 2 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-24 | 15 | ? | 0% | 0% | 13 | 0 |
| 2026-10-24 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-25 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 3 | ? | 0% | 0% | 1 | 0 |