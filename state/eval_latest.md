# Watchtower Pipeline Eval — 2026-08-03T00:06:28Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 20 |
| After dedup + CVE merge | 20 |
| Sent to Groq | 20 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/20 (15.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,769 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6252

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 71.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 16 |
| `bleepingcomputer` | 3 |
| `cloudflare_blog` | 1 |
| `krebs` | 0 |
| `cisa_kev` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-01 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-01 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-02 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-02 | 2 | 2 | 100% | 0% | 2 | 0 |