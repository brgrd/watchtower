# Watchtower Pipeline Eval — 2026-10-31T12:11:14Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 133 |
| After dedup + CVE merge | 131 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/133 (1.5%)** |

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

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.5 | Mean shelf_days: 0.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 124 |
| `thehackernews` | 3 |
| `cisa_kev` | 2 |
| `securityweek` | 1 |
| `talos_blog` | 1 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-26 | 3 | ? | 0% | 0% | 1 | 0 |
| 2026-10-27 | 1 | ? | 0% | 0% | 0 | 1 |
| 2026-10-27 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-10-29 | 8 | ? | 0% | 0% | 7 | 0 |
| 2026-10-30 | 6 | ? | 0% | 0% | 3 | 0 |
| 2026-10-30 | 7 | ? | 0% | 0% | 7 | 0 |