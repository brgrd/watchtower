# Watchtower Pipeline Eval — 2026-04-12T22:49:05Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 32 |
| After dedup + CVE merge | 32 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/32 (9.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,748 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8496

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 91 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 50% generic

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
| `nvd` | 30 |
| `bleepingcomputer` | 1 |
| `cloudflare_blog` | 1 |
| `cisa_alerts` | 0 |
| `cisa_kev` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-07 | 5 | 2 | 100% | 40% | 5 | 0 |
| 2026-04-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-09 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-04-10 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-11 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-11 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 3 | 100% | 0% | 3 | 0 |