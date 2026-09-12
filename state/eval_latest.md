# Watchtower Pipeline Eval — 2026-09-12T22:10:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 41 |
| After dedup + CVE merge | 39 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/41 (4.9%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 35 |
| `thehackernews` | 2 |
| `darkreading` | 2 |
| `bleepingcomputer` | 1 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-10 | 11 | ? | 0% | 0% | 4 | 0 |
| 2026-09-10 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-10 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-09-11 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-11 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-11 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-09-12 | 15 | ? | 0% | 0% | 15 | 0 |