# Watchtower Pipeline Eval — 2026-07-25T23:07:42Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 9 |
| After dedup + CVE merge | 8 |
| Sent to Groq | 8 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/9 (33.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,019 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6950

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 50.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 0% specific, 50% generic

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
| `nvd` | 4 |
| `bleepingcomputer` | 3 |
| `thehackernews` | 2 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-24 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-07-24 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-24 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-25 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-25 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-25 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-25 | 3 | ? | 100% | 0% | 3 | 0 |