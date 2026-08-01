# Watchtower Pipeline Eval — 2026-08-01T09:13:01Z

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
- **Payload**: 10,819 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7285

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

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
| `nvd` | 64 |
| `bleepingcomputer` | 2 |
| `thehackernews` | 2 |
| `cisa_kev` | 0 |
| `gh_security_blog` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-31 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-31 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-31 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-07-31 | 3 | 3 | 100% | 100% | 3 | 0 |