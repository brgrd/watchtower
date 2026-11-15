# Watchtower Pipeline Eval — 2026-11-15T01:45:54Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 5 |
| After dedup + CVE merge | 5 |
| Sent to Groq | 5 |
| Groq findings returned | 0 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/5 (100.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**5 cards** — P1: 0, P2: 0, P3: 5

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 14 / 0 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **5** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `securityweek` | 2 |
| `thehackernews` | 1 |
| `krebs` | 0 |
| `cloudflare_blog` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-10 | 5 | ? | 0% | 0% | 3 | 0 |
| 2026-11-10 | 11 | ? | 0% | 0% | 9 | 1 |
| 2026-11-11 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-11-12 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-13 | 9 | ? | 0% | 0% | 7 | 1 |
| 2026-11-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-14 | 15 | ? | 0% | 0% | 15 | 0 |