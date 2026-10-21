# Watchtower Pipeline Eval — 2026-10-21T10:00:49Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 524 |
| After dedup + CVE merge | 520 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/524 (0.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 72.5 / 70 |
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
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `thehackernews` | 6 |
| `cisa_kev` | 6 |
| `bleepingcomputer` | 3 |
| `securityweek` | 3 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-20 | 15 | ? | 0% | 0% | 1 | 0 |
| 2026-10-20 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-10-20 | 7 | ? | 0% | 0% | 6 | 0 |