# Watchtower Pipeline Eval — 2026-08-23T23:29:22Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 22 |
| After dedup + CVE merge | 4 |
| Sent to Groq | 4 |
| Groq findings returned | 0 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/22 (18.2%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**4 cards** — P1: 0, P2: 0, P3: 4

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 62.5 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 21 |
| `bleepingcomputer` | 1 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| `thehackernews` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-23 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-23 | 14 | ? | 0% | 0% | 14 | 0 |
| 2026-08-23 | ? | ? | ?% | ?% | ? | ? |
| 2026-08-23 | ? | ? | ?% | ?% | ? | ? |
| 2026-08-23 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-08-23 | 3 | ? | 0% | 0% | 3 | 0 |