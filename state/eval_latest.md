# Watchtower Pipeline Eval — 2026-08-09T11:38:03Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 102 |
| After dedup + CVE merge | 102 |
| Sent to Groq | 102 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/102 (2.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,482 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6843

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 35.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 33% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 56 |
| `msrc_update_guide` | 46 |
| `gh_security_blog` | 0 |
| `bleepingcomputer` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-08 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-08-08 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-08 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-08 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-08-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-09 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-09 | 3 | 1 | 100% | 67% | 3 | 0 |