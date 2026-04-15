# Watchtower Pipeline Eval — 2026-04-15T10:24:23Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 185 |
| After dedup + CVE merge | 185 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/185 (1.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,247 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8371

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 124.7 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.7 | Mean shelf_days: 0.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 67% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 123 |
| `nvd` | 46 |
| `bleepingcomputer` | 2 |
| `cisa_kev` | 2 |
| `thehackernews` | 2 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-11 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-13 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-14 | 3 | 3 | 100% | 100% | 0 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |