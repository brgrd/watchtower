# Watchtower Pipeline Eval — 2026-11-12T01:27:37Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 823 |
| After dedup + CVE merge | 821 |
| Sent to Groq | 3 |
| Groq findings returned | 0 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/823 (0.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**3 cards** — P1: 0, P2: 0, P3: 3

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 500 |
| `bsi_germany` | 250 |
| `msrc_update_guide` | 29 |
| `bleepingcomputer` | 10 |
| `securityweek` | 9 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-06 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-11-06 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-11-08 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-11-08 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-10 | 5 | ? | 0% | 0% | 3 | 0 |
| 2026-11-10 | 11 | ? | 0% | 0% | 9 | 1 |
| 2026-11-11 | 1 | ? | 0% | 0% | 0 | 0 |