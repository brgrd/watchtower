# Watchtower Pipeline Eval — 2026-11-18T13:48:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 769 |
| After dedup + CVE merge | 758 |
| Sent to Groq | 120 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/769 (2.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 87.3 / 90 |
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
| EPSS | 1 | 7% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 500 |
| `bsi_germany` | 199 |
| `gcp_security` | 30 |
| `securityweek` | 10 |
| `thehackernews` | 8 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-13 | 9 | ? | 0% | 0% | 7 | 1 |
| 2026-11-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-14 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-15 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-11-16 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-17 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-17 | 9 | ? | 0% | 0% | 4 | 2 |