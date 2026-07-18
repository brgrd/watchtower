# Watchtower Pipeline Eval — 2026-07-18T21:00:21Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 68 |
| After dedup + CVE merge | 68 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/68 (4.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,588 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7664

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 60 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 0% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 64 |
| `bleepingcomputer` | 4 |
| `cisa_alerts` | 0 |
| `cisa_kev` | 0 |
| `thehackernews` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-17 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-07-17 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-17 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-17 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-18 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-18 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-18 | 2 | 1 | 100% | 0% | 2 | 0 |