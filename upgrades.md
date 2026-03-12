# Watchtower Upgrades Tracker

Use this as a running manager of upgrades. Check boxes as work is completed.

## How to use
- Keep each item open until code, tests, and docs are complete.
- Add links to PRs/issues under each item.
- Move completed items to the bottom of each section if preferred.

---

## Priority 1 — Reliability & Correctness

- [x] **DST-safe New York time handling**
  - Replace fixed ET offset logic with timezone-aware conversion (`America/New_York`).
  - Scope: history bucketing + any UI/run-window displays.
  - Current findings:
    - [agent/state.py](agent/state.py#L118-L133)
    - [agent/rendering.py](agent/rendering.py#L134)
    - [agent/runner.py](agent/runner.py#L1392-L1407)

- [x] **Deterministic seen-hash retention**
  - Replace set slicing approach with timestamped or ordered eviction to avoid non-deterministic drops.
  - Current findings: [agent/state.py](agent/state.py#L55-L65)

- [x] **Harden private host validation**
  - Use CIDR-accurate checks (`172.16.0.0/12`) and explicit localhost handling.
  - Validate IPv4/IPv6/private ranges via robust parsing.
  - Current findings: [agent/ingest.py](agent/ingest.py#L17-L40)

---

## Priority 2 — Architecture & Maintainability

- [x] **Modularize `runner.py`**
  - Split into focused modules (ingest, analysis, scoring, rendering, state).
  - Status: modules were added and wired.
  - Follow-up remaining: thin `runner.py` by removing legacy duplicated logic and keeping orchestration-only flow.
  - Source references:
    - [agent/ingest.py](agent/ingest.py)
    - [agent/analysis.py](agent/analysis.py)
    - [agent/scoring.py](agent/scoring.py)
    - [agent/rendering.py](agent/rendering.py)
    - [agent/state.py](agent/state.py)
    - [agent/runner.py](agent/runner.py)

- [x] **Resolve planner direction**
  - Either wire full plan generation/dispatch flow or remove dormant planner indirection.
  - Status: removed static one-step `dispatch_plan()` runtime path from orchestrator.
  - Next iteration option: re-introduce planning only with model-driven multi-step plan + tests.
  - Source references:
    - [agent/runner.py](agent/runner.py#L2470-L2471)
    - [agent/planning.py](agent/planning.py)

---

## Priority 3 — Quality & Operations

- [x] **Align mode defaults across docs/config**
  - Ensure README and runtime config describe the same default placeholder behavior.
  - Resolved alignment:
   - README local default: [README.md](README.md#L18-L24)
   - Config local default: [agent/config.yaml](agent/config.yaml#L14)

- [x] **Increase coverage in high-risk paths**
  - Add tests for plan dispatch behavior, Groq error/fallback paths, and weekly aggregate transforms.
  - Focus especially on modules currently under-covered.
  - Current signal (2026-03-12 run): coverage gate recovered to 23.35% with added planner tests.
  - Follow-on depth still recommended for:
   - [agent/planning.py](agent/planning.py)
   - [agent/analysis.py](agent/analysis.py)
   - [agent/ingest.py](agent/ingest.py)
   - [agent/state.py](agent/state.py)

---

## Ordered Next Execution Plan

1. [x] **Finalize planner direction (first)**
  - Completed: static planner indirection removed from runtime.

2. [x] **Fix DST correctness (second)**
  - Completed in runtime path for history bucketing and rendering current-day selection.

3. [x] **Fix deterministic seen retention (third)**
  - Completed: seen storage supports timestamped map schema with deterministic pruning order and legacy compatibility.

4. [x] **Tighten host safety checks (fourth)**
  - Completed: `ipaddress`-based checks implemented with explicit localhost handling.

5. [x] **Align docs/config defaults (fifth)**
  - Completed: runtime config now matches README local default; CI continues to force real mode.

6. [x] **Recover coverage gate and raise confidence (parallel with 1-5)**
  - Completed: added targeted planning tests; coverage gate now passes (>22%).
  - Next depth: add analysis/ingest/state-focused tests for stronger confidence.

---

## Optional Backlog Enhancements

- [x] Add structured run metrics (feed reliability, model failures, parse failures).
- [x] Add schema validation before writing report artifacts.
- [x] Add stronger feed health scoring and auto-disable/retry policy for noisy sources.

---

## Phase 2 — Functional Enhancements

These items address the two user patterns currently in tension: the **active analyst** (checking in, filtering, reading findings) and the **passive monitor** (doesn't log in regularly, needs critical signals surfaced without engagement). The current design serves the active analyst well. The items below close the passive-monitor gap and deepen intelligence quality.

### 🔴 High Priority

- [ ] **Push digest / webhook alerts**
  - Send a scheduled email or webhook (Slack/Teams) when P1 count exceeds a threshold, a tracked finding matches a user-defined keyword watchlist, or a finding persists across N consecutive runs.
  - The Alerts tab in the Domain Activity rail is the natural home for subscription/filter configuration UI.
  - Scope: new `agent/notify.py` module; config block in `config.yaml` for targets/thresholds; wired into `_run()` post-card-build.

- [ ] **"Since your last visit" catch-up view**
  - Store the last page-open timestamp in `localStorage`. On return, render a collapsible "Catch-up since [date]" strip at the top — only findings new since that timestamp, ordered by priority.
  - Solves the passive-monitor problem at the UI layer with no backend changes needed.
  - Scope: JS-only; reads `CARDS` data-attribute timestamps, compares against stored `wt.last_visit`.

- [x] **Finding shelf life — `first_seen`, `run_count`, `last_seen`**
  - Track how long each finding ID (or CVE) has been active across runs. A finding present across 6 consecutive runs is categorically more important than a one-run blip.
  - Implemented in Phase 3 — see below.

### 🟡 Medium Priority

- [x] **Threat velocity / acceleration signal**
  - Compute findings-per-domain-per-day over a 7-day rolling window. Flag domains where the rate is accelerating (e.g., 1 → 5 findings/day in 3 days). Directly addresses AI-assisted campaigns that hit multiple domains simultaneously and fast.
  - `_compute_velocity()` in `runner.py` compares avg(last 2 days) vs avg(prior 2 days) per domain; `velocity` dict flows to `_build_domain_rank_html` (`↑↑`/`↑`/`↓` chips) and `_build_threat_map_svg` (orange aura glow for accelerating nodes).

- [x] **MITRE ATT&CK mapping**
  - Groq prompt upgraded to v2: `tactic_name` (one of 14 ATT&CK tactics) and `technique_name` per finding. Richer risk-score rubric (+30 actively exploited, +15 PoC, +15 critical infra). Exec-summary now requires named CVEs/products.
  - `tactic_name`/`technique_name` pass-through in `_findings_to_cards`; tactic chip on cluster cards; 14-button filter strip above Top Findings with JS filter by `data-tactic`.
  - Kill-chain coverage bar (count of distinct tactics hit per window) deferred to Phase 3.

- [x] **AI Threat explicit domain tag**
  - `ai_threat` added to `config.yaml` taxonomy with 30 signals (llm, prompt injection, model poisoning, deepfake, jailbreak, RAG poisoning, adversarial ML, etc.).
  - Constellation node at (680, 68) with edges to `cloud_iam`, `supply_chain`, `identity`.
  - `_DOMAIN_PRIORITY_FIRST` classifier list ensures `ai_threat` is evaluated before broad `os_kernel` signals.

- [x] **Threat heatmap calendar**
  - 14-day contribution grid injected between the constellation map and the weekly scope section. Per-cell tiers: grey (no data), green (risk < 30), blue (30–59), amber (60–79), red (80+). Each cell has a tooltip with date, count, and P1s.
  - `_build_calendar_html(history_days)` in `runner.py`; pure HTML/CSS, no new data sources.

- [ ] **Domain sparklines in the Overview rail**
  - Replace static domain bars with 7-day sparklines (one data point per day) per domain. Rising trend over three days is a different signal than a one-day spike.
  - Scope: computed from `history_days` in renderer; inline SVG paths per domain row.

### 🟢 Lower Priority

- [ ] **EPSS-based time-to-exploit estimation**
  - Fetch EPSS scores from FIRST.org for each CVE found this window. Badge high-EPSS findings differently from low-EPSS ones even when CVSS is similar. EPSS is a stronger exploitation predictor than CVSS alone.
  - Scope: new `_enrich_epss()` helper in `ingest.py`; adds `epss` field to items; new badge variant `.epss-badge` in HTML.

- [ ] **Watchlist / follow mode**
  - User-defined list of CVE IDs, vendor names, product keywords, and MITRE techniques (configured in `config.yaml` or a local `watchlist.yaml`). Matched findings are pinned at the top of Top Findings and persist until dismissed via `state/dismissed.json`.
  - Scope: filter pass in `_run()` after card build; `wt.dismissed` key in localStorage for UI-layer dismiss.

- [ ] **Cross-run IOC extraction (Forensics tab)**
  - Extract IPs, domains, file hashes, and registry keys from source article text. Deduplicate and cross-reference across findings. Populate the currently-placeholder Forensics tab in the Domain Activity rail.
  - Scope: new `_extract_iocs()` helper in `scoring.py`; `state/ioc_ledger.json` for persistence; Forensics tab HTML wired in `_write_index_html`.

- [ ] **Interactive constellation — blast-radius path highlighting**
  - On node click, animate directed paths from the selected node to all reachable downstream domains using the existing `_TM_EDGES` graph. Makes blast-radius reasoning visual rather than implicit.
  - Scope: JS-only change to `selectDomain()` / SVG edge rendering in `_build_threat_map_svg`.

- [ ] **Unread count in browser tab title**
  - Update `document.title` with the P1 new-finding count (`[2 P1] Watchtower — InfraSec Briefing`) so users with the tab open but doing other work get a passive signal.
  - Scope: 3-line JS addition in `_write_index_html`.

---

## Phase 3 — Intelligence Depth & Passive-Monitor Parity

With Phase 2 surface-area features shipped, Phase 3 targets three goals: **closing remaining passive-monitor gaps** (alerts, catch-up, persistence), **hardening the intelligence pipeline** (contract validation, EPSS enrichment), and **deepening interactivity** (sparklines, IOC tab, blast-radius animation).

### Recommended Sequencing

| Order | Item | Status |
|-------|------|--------|
| 1 | Tactic contract enforcement | ✅ Done |
| 2 | Kill-chain coverage bar | ✅ Done |
| 3 | Finding shelf life | ✅ Done |
| 4 | Domain sparklines | Next — all data available, no backend change |
| 5 | EPSS enrichment | Strongest signal upgrade per unit effort |
| 6 | Catch-up view | Pure JS, closes passive-monitor gap |
| 7 | Push alerts | Highest passive-monitor payoff; new module required |

### 🔴 High Priority

- [x] **MITRE tactic contract enforcement**
  - `_normalize_tactic(raw)` in `analysis.py`: 14-entry canonical dict, alias map (c2, privesc, evasion, etc.), 6-char prefix fallback, empty string on unrecognized values. Groq can no longer silently break the tactic filter strip.
  - Parameterized test coverage recommended as follow-up.

- [x] **Kill-chain coverage bar**
  - Row of 14 square pips above the tactic filter strip; filled (blue) = tactic present in current window, hollow = absent. Label: "N / 14 tactics covered". Python-rendered at build time; no JS dependency.

- [x] **Finding shelf life — `first_seen`, `run_count`, `last_seen`**
  - `FINDING_SHELF_FILE = state/finding_shelf.json` per finding ID (sha256 title prefix). `_update_shelf(cards)` increments `run_count` once per calendar day, applies +5 risk_score boost per run beyond 1 (capped +20). Entries pruned after 30d inactivity. Orange `Nd` shelf badge on cluster cards for findings ≥ 1 day old.

### 🟡 Medium Priority

- [ ] **Domain sparklines in the Overview rail**
  - Replace static domain score bars with 7-day inline SVG sparklines (one point per day). A 3-day rising trend is a different signal than a one-day spike at the same current score.
  - Scope: computed from `history_days` in `_build_domain_rank_html`; inline `<svg>` polyline per row (~30 px tall); no new data sources needed.

- [ ] **EPSS-based exploitation probability badge**
  - Fetch EPSS scores from `https://api.first.org/data/v1/epss?cve=CVE-XXXX` for each CVE found this window. Badge high-EPSS findings (> 0.4) with a distinct color even when CVSS is similar. EPSS is a consistently stronger real-world exploitation predictor than CVSS alone.
  - Scope: `_enrich_epss(cards)` in `ingest.py`; `state/epss_cache.json` (TTL 24 h) to avoid re-fetching; `.epss-badge` CSS variant.

- [ ] **"Since your last visit" catch-up view**
  - Store the last page-open timestamp in `localStorage`. On return after > 4 hours, render a collapsible "Catch-up since [date]" strip at the top — only findings new since that timestamp, ordered by priority.
  - Zero backend cost; entirely closes the passive-monitor check-in friction problem.
  - Scope: JS-only; reads `CARDS` timestamps vs. `wt.last_visit` in `localStorage`; collapsible `<details>` strip.

- [ ] **Push digest / webhook alerts**
  - Notify when: P1 count exceeds threshold, a keyword watchlist term matches a new finding, or a finding persists N consecutive runs without action.
  - Scope: new `agent/notify.py` (email via `smtplib` + Slack/Teams webhook); `notifications:` block in `config.yaml`; wired into `_run()` post-card-build; test with mocked HTTP.

### 🟢 Lower Priority

- [ ] **Watchlist / follow mode**
  - User-defined CVE IDs, vendor names, product keywords, MITRE techniques in `config.yaml` or `watchlist.yaml`. Matched findings pinned to top of Top Findings; persist until dismissed via `state/dismissed.json`.
  - Scope: filter pass in `_run()`; `wt.dismissed` `localStorage` key for UI-layer dismiss.

- [ ] **Cross-run IOC extraction (Forensics tab)**
  - Extract IPs, domains, file hashes, registry keys from source article text; deduplicate and cross-reference across findings; populate the currently-placeholder Forensics tab.
  - Scope: `_extract_iocs()` in `scoring.py`; `state/ioc_ledger.json`; Forensics tab HTML wired in `_write_index_html`.

- [ ] **Interactive constellation — blast-radius path highlighting**
  - On node click, animate directed paths to all reachable downstream domains via `_TM_EDGES`. Makes blast-radius reasoning visual rather than implicit.
  - Scope: JS-only change to `selectDomain()` + SVG edge rendering in `_build_threat_map_svg`.

- [ ] **Unread count in browser tab title**
  - Update `document.title` with P1 count (`[2 P1] Watchtower — InfraSec Briefing`) for passive signal to users who keep the tab open.
  - Scope: 3-line JS addition; zero risk.

---

## Phase 4 — Pipeline Quality & Structural Health

Phase 3 closed the most visible passive-monitor and intelligence-depth gaps. Phase 4 addresses the underlying **pipeline quality risks** that will compound as data volume and feature count grow — primarily deduplication fidelity, model resilience, test coverage depth, and `runner.py` size.

### Recommended Sequencing

| Order | Item | Why |
|-------|------|-----|
| 1 | Split `runner.py` HTML rendering | Most impactful maintainability move; 3 200-line file is a growing liability |
| 2 | CVE-anchored dedup before Groq | Eliminates the most common finding-quality defect |
| 3 | Groq retry + model fallback | Prevents silent empty-result runs under rate pressure |
| 4 | Shelf life decay / resolution | Prevents stale "always-boosted" findings from dominating forever |
| 5 | Tactic normalization tests | Parameterized regression guard for the new normalization path |
| 6 | Coverage push (analysis + ingest) | `analysis.py` at 10%, `ingest.py` at 9% — highest regression risk in codebase |

### 🔴 High Priority

- [x] **Split `runner.py` HTML rendering into `agent/html_builder.py`**
  - `runner.py` is now ~3 200 lines. The HTML template string, CSS block, JS block, SVG constellation builder, domain rank builder, calendar builder, and tactic strip are all inlined. This makes diffs nearly unreadable and tests impossible to write without executing the entire orchestrator.
  - Extract all `_build_*` and `_write_index_html` functions into `agent/html_builder.py`. `runner.py` calls `html_builder.write_index(path, cards, ...)`. Each builder becomes independently testable.
  - Scope: new `agent/html_builder.py`; `runner.py` imports and delegates; existing tests unaffected; new unit tests for builders become practical.

- [x] **CVE-anchored deduplication before Groq analysis**
  - Currently deduplication is hash-based on item titles. Two feed articles about the same CVE with slightly different headlines both reach Groq, producing duplicate or near-duplicate findings that inflate counts and consume tokens.
  - After ingest, group items by extracted CVE IDs; merge groups into a single enriched item (combined text, all sources). Non-CVE items remain as-is.
  - Scope: `_merge_by_cve(items)` helper in `runner.py` or `ingest.py`; called after `deduplicate()` and before `groq_analyze_briefing()`.

- [ ] **Groq retry with backoff + smaller-model fallback**
  - A single Groq API call with no retry beyond basic error handling. Rate-limit hits (HTTP 429) silently produce empty results — the run succeeds but the briefing is blank.
  - Add exponential backoff retry (3 attempts, 2/4/8 s delays) for 429/5xx. On persistent failure, fall back to a smaller model (e.g., `llama3-8b-8192` if `llama3-70b` is configured) with a warning in `groq_status`.
  - Scope: `agent/analysis.py` — wrap Groq call in `_call_with_retry()`; `groq_status` extended to include `"fallback"` state; surfaced in run metrics panel.

### 🟡 Medium Priority

- [ ] **Shelf life decay and resolved-finding suppression**
  - The current shelf implementation boosts scores indefinitely up to +20 and never downgrades. A CVE that was patched 3 runs ago should not continue receiving a persistence boost.
  - Add a `resolved` flag to shelf entries, settable when `patch_status == "patched"`. Resolved findings: boost is zeroed, badge changes to grey `Nd (resolved)`. Shelf entry retained for 7 days post-resolution then pruned.
  - Scope: `_update_shelf()` in `runner.py` — check `patch_status`; add `.shelf-badge--resolved` CSS variant.

- [ ] **Parameterized tactic normalization tests**
  - `_normalize_tactic()` covers ~15 alias paths but has zero test coverage. A single Groq prompt change could silently break all tactic chips and the coverage bar.
  - Add `tests/test_tactic_normalization.py` with parameterized cases for: exact match, alias match (c2, privesc), prefix match, garbage input, empty string, `None`.
  - Scope: `tests/test_tactic_normalization.py` — ~30 lines; `analysis.py` exports `_normalize_tactic` for direct import.

- [ ] **Coverage push: `analysis.py` and `ingest.py`**
  - `analysis.py` is at 10% coverage, `ingest.py` at 9%. Both sit on the critical data path: Groq response parsing, card building, feed fetching, CVE extraction. Any regression here produces silent bad output rather than a test failure.
  - Target: `analysis.py` → 40%, `ingest.py` → 35%. Focus on `_findings_to_cards` (edge cases), `_normalize_tactic` (see above), `groq_analyze_briefing` (mock Groq), `_fetch_feed` (mock HTTP), and `_enrich_kev`.
  - Scope: `tests/test_analysis.py`, `tests/test_ingest.py` — new files or additions; mock `httpx` / `groq` client.

### 🟢 Lower Priority

- [ ] **Shelf life cross-run CVE identity**
  - Currently shelf keys are `sha256(title)[:16]`. Two headlines about the same CVE with different wording get different shelf entries. Change the shelf key to the primary CVE ID when one is extractable, falling back to title hash.
  - Scope: `_update_shelf()` — `_extract_cves()` on title; use first CVE as key if present.

- [ ] **Groq token budget monitoring**
  - Log estimated prompt token count before each Groq call (approx. 4 chars/token). If the payload exceeds 80% of the model's context window, truncate `news_articles` block first, then `recent_cves`, and warn in run metrics.
  - Scope: `agent/analysis.py` — `_estimate_tokens()` helper; truncation pass before JSON serialisation.

- [ ] **Feed source geographic tagging**
  - Feeds already carry `country` metadata but it is not aggregated at the run level. A KPI showing the geographic distribution of source articles (US 40%, EU 30%, APAC 20%) helps assess coverage blindspots.
  - Scope: aggregate in `run_metrics` dict; render as a small bar in the Feeds tab.

---

## Change Log

- 2026-03-12: Tracker created from project review recommendations.
- 2026-03-12: Implemented modular split into `ingest.py`, `analysis.py`, `scoring.py`, `rendering.py`, and `state.py`; production runner wired to split modules.
- 2026-03-12: Re-reviewed remaining items; corrected planner status to open; added ordered execution plan for next implementation cycle.
- 2026-03-12: Removed static planner indirection from runtime path; marked planner-direction item complete.
- 2026-03-12: Implemented DST-safe ET conversion (`America/New_York`) in active state/rendering path with robust fallback when tzdata is unavailable.
- 2026-03-12: Implemented deterministic seen-hash retention using timestamped map schema with deterministic purge ordering and backward-compatible legacy set/hash support.
- 2026-03-12: Hardened private-host validation with CIDR-aware IP checks and explicit localhost blocking.
- 2026-03-12: Aligned placeholder-mode defaults between docs and runtime config.
- 2026-03-12: Added planner dispatch unit tests and recovered coverage gate (23.35%).
- 2026-03-12: Implemented structured run metrics, schema validation, and feed health tracking; added CVE badges, search/filter bar, All Domains reset chip, run metrics panel in Feeds tab.
- 2026-03-12: Added Phase 2 functional and UI enhancement backlog from threat-landscape review.
- 2026-03-12: Completed all Phase 2 medium-priority items — 14-day threat heatmap calendar, velocity/acceleration signal with constellation glow, `ai_threat` domain (30 signals, priority-first classifier), MITRE ATT&CK tactic chips + 14-button filter strip + Groq prompt v2. Fixed JS regex `SyntaxWarning`. 151 tests pass, 31% coverage.
- 2026-03-12: Opened Phase 3 backlog: tactic contract enforcement, kill-chain coverage bar, finding shelf life, domain sparklines, EPSS enrichment, catch-up view, push alerts, watchlist, IOC extraction, blast-radius highlighting, tab title unread count.
- 2026-03-12: Completed Phase 3 high-priority items — `_normalize_tactic()` with alias map + prefix fallback (analysis.py), 14-pip kill-chain coverage bar (Python-rendered, runner.py), `_update_shelf()` with scoring boost + orange shelf badge (runner.py). 151 tests pass, 31% coverage.
- 2026-03-12: Opened Phase 4 backlog: runner.py HTML split, CVE-anchored dedup, Groq retry/fallback, shelf decay, tactic normalization tests, coverage push for analysis.py and ingest.py.
- 2026-03-12: Completed Phase 4 items 1 & 2 — extracted all `_build_*`/`_write_index_html`/`_TM_NODES`/`_TM_EDGES` into `agent/html_builder.py` (runner.py shrunk from ~3 200 to ~1 760 lines, html_builder.py at 55% coverage immediately); added `_merge_by_cve()` union-find grouping in `agent/ingest.py` + wired after `deduplicate()` in `_run()`. All tests pass, 40% coverage.
