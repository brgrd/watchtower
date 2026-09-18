# Watchtower Pipeline Eval — 2026-09-18T21:35:27Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 623 |
| After dedup + CVE merge | 618 |
| Sent to Groq | 4 |
| Groq findings returned | 0 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/623 (0.6%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**4 cards** — P1: 0, P2: 0, P3: 4

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 72.5 / 85 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 0.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 405 |
| `bsi_germany` | 171 |
| `thehackernews` | 8 |
| `bleepingcomputer` | 7 |
| `securityweek` | 7 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-14 | 3 | ? | 0% | 0% | 2 | 0 |
| 2026-09-15 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-16 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-09-17 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-09-17 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-18 | 1 | ? | 0% | 0% | 1 | 0 |