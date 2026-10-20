# Watchtower Pipeline Eval — 2026-10-20T11:23:38Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 315 |
| After dedup + CVE merge | 314 |
| Sent to Groq | 1 |
| Groq findings returned | 0 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/315 (0.3%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**1 cards** — P1: 0, P2: 0, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 184 |
| `bsi_germany` | 121 |
| `thehackernews` | 4 |
| `bleepingcomputer` | 2 |
| `securityweek` | 2 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-16 | 9 | ? | 0% | 0% | 5 | 0 |
| 2026-10-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-20 | 15 | ? | 0% | 0% | 1 | 0 |