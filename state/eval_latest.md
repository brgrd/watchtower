# Watchtower Pipeline Eval — 2026-10-11T12:38:03Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 179 |
| After dedup + CVE merge | 179 |
| Sent to Groq | 120 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/179 (8.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
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
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 178 |
| `thehackernews` | 1 |
| `cisa_kev` | 0 |
| `krebs` | 0 |
| `bleepingcomputer` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-04 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-10-06 | 3 | ? | 0% | 0% | 2 | 0 |
| 2026-10-07 | 4 | ? | 0% | 0% | 4 | 0 |
| 2026-10-07 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-10-08 | 5 | ? | 0% | 0% | 4 | 0 |
| 2026-10-09 | 13 | ? | 0% | 0% | 7 | 0 |
| 2026-10-10 | 15 | ? | 0% | 0% | 15 | 0 |