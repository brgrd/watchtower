# Watchtower Pipeline Eval — 2026-10-02T21:16:28Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 523 |
| After dedup + CVE merge | 516 |
| Sent to Groq | 5 |
| Groq findings returned | 0 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/523 (1.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**5 cards** — P1: 0, P2: 0, P3: 5

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 58 / 70 |
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
| EPSS | 1 | 20% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 314 |
| `bsi_germany` | 157 |
| `cloudflare_blog` | 10 |
| `bleepingcomputer` | 7 |
| `darkreading` | 7 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-27 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-28 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-28 | 5 | ? | 0% | 0% | 1 | 1 |
| 2026-09-30 | 7 | ? | 0% | 0% | 7 | 0 |
| 2026-09-30 | 3 | ? | 0% | 0% | 1 | 0 |
| 2026-10-01 | 10 | ? | 0% | 0% | 7 | 0 |
| 2026-10-02 | 1 | ? | 0% | 0% | 0 | 0 |