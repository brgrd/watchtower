# Watchtower Pipeline Eval — 2026-09-02T09:29:11Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 161 |
| After dedup + CVE merge | 159 |
| Sent to Groq | 3 |
| Groq findings returned | 0 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/161 (1.9%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**3 cards** — P1: 0, P2: 0, P3: 3

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
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
| `nvd` | 141 |
| `thehackernews` | 5 |
| `bleepingcomputer` | 3 |
| `securityweek` | 3 |
| `darkreading` | 3 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-30 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-31 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 9 | ? | 0% | 0% | 9 | 0 |
| 2026-09-02 | 2 | ? | 0% | 0% | 0 | 0 |