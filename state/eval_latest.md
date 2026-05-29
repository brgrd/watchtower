# Watchtower Pipeline Eval — 2026-05-29T12:24:47Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 539 |
| After dedup + CVE merge | 539 |
| Sent to Groq | 120 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/539 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,267 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7488

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 60 |
| Tactic coverage | 67% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 31 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 100% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 215 |
| `msrc_update_guide` | 154 |
| `bsi_germany` | 153 |
| `bleepingcomputer` | 6 |
| `thehackernews` | 4 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-26 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-05-27 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-27 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-27 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-28 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-05-28 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-28 | 3 | ? | 100% | 0% | 3 | 0 |