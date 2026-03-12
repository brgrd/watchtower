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

- [ ] **Finding shelf life — `first_seen`, `run_count`, `last_seen`**
  - Track how long each finding ID (or CVE) has been active across runs. A finding present across 6 consecutive runs is categorically more important than a one-run blip.
  - Surface as a "Days Active" micro-badge on cards and feed into delta scoring.
  - Scope: `state/finding_shelf.json`; update during card merge in `_run()`; new badge class in HTML renderer.

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

| Order | Item | Why first |
|-------|------|-----------|
| 1 | Tactic contract enforcement | Prevents silent filter breakage today; 1-day effort |
| 2 | Kill-chain coverage bar | Completes the MITRE story with no new data; 0.5-day effort |
| 3 | Finding shelf life | Unlocks persistence-aware scoring for all future features |
| 4 | Domain sparklines | High UX value, all data already available |
| 5 | EPSS enrichment | Strongest signal upgrade per unit of effort |
| 6 | Catch-up view | Closes passive-monitor gap at pure JS cost |
| 7 | Push alerts | Requires new module; highest passive-monitor payoff |

### 🔴 High Priority

- [ ] **MITRE tactic contract enforcement**
  - The Groq prompt requests `tactic_name` from a 14-item list but the response is not validated. Groq occasionally returns abbreviated or hallucinated names that silently break the tactic filter strip (e.g., `"Priv Esc"` instead of `"Privilege Escalation"`).
  - Add a normalization pass in `_findings_to_cards`: fuzzy-match the returned string against canonical 14 tactics; coerce partial matches; null-out unrecognized values; log coercions for monitoring.
  - Scope: `agent/analysis.py` — ~15-line normalization dict + guard; add parameterized test cases for each bad-string variant.

- [ ] **Kill-chain coverage bar**
  - The 14-tactic filter buttons exist but there is no _coverage_ signal: how many of the 14 ATT&CK tactics appear in this window's findings? A window covering 11 tactics is categorically more alarming than one covering 3.
  - Render a row of 14 pips above the tactic strip (filled = tactic present in findings, hollow = absent). Show count label: "7 / 14 tactics covered".
  - Scope: JS-only; single pass over `CARDS` at page load; `.tactic-pip` CSS; no backend change.

- [ ] **Finding shelf life — `first_seen`, `run_count`, `last_seen`**
  - A finding persisting across 6 consecutive runs is categorically more important than a one-run blip, yet both currently render identically.
  - Track finding IDs (CVE + title hash) in `state/finding_shelf.json`. Surface a "Days Active" micro-badge on cards. Feed into scoring: +5 per additional consecutive run seen (capped at +20).
  - Scope: `state/finding_shelf.json`; update in `_run()` after card build; `.shelf-badge` CSS in renderer; `_update_shelf()` helper in `state.py`.

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
