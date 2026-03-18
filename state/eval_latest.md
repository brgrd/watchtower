# Watchtower Pipeline Eval — 2026-03-18T20:53:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 253 |
| After dedup + CVE merge | 252 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/253 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,263 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10382

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 106 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 111 |
| `nvd` | 100 |
| `securityweek` | 10 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**10 feeds returned 0 items this run.**