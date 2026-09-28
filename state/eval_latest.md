# Watchtower Pipeline Eval — 2026-09-28T21:50:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 539 |
| After dedup + CVE merge | 530 |
| Sent to Groq | 5 |
| Groq findings returned | 0 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/539 (0.9%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**5 cards** — P1: 0, P2: 0, P3: 5

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **3** | Persistent (>5): **1** | Resolved: **0**
- Mean run_count: 2.8 | Mean shelf_days: 31

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 290 |
| `bsi_germany` | 158 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 10 |
| `thehackernews` | 10 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-24 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-24 | 12 | ? | 0% | 0% | 7 | 0 |
| 2026-09-25 | 9 | ? | 0% | 0% | 3 | 0 |
| 2026-09-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-26 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-09-27 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-28 | 15 | ? | 0% | 0% | 15 | 0 |