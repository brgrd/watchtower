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

- [ ] **Threat velocity / acceleration signal**
  - Compute findings-per-domain-per-day over a 7-day rolling window. Flag domains where the rate is accelerating (e.g., 1 → 5 findings/day in 3 days). Directly addresses AI-assisted campaigns that hit multiple domains simultaneously and fast.
  - Surface as a velocity arrow (`↑↑`) on the domain rank bar and a KPI chip.
  - Scope: computed from `ledger.jsonl` history in `state.py`; new `velocity` dict passed to renderer.

- [ ] **MITRE ATT&CK mapping**
  - Extend Groq prompt to return `tactic` (TA####) and `technique` (T####) fields per finding.
  - Enables filtering by kill-chain phase, lets the passive monitor quickly distinguish pre- vs post-breach threats, and feeds a kill-chain coverage bar (how many of the 14 tactics are being hit this window).
  - Scope: prompt update in `analysis.py`; new `tactic`/`technique` fields on cards; kill-chain filter strip above Top Findings in HTML.

- [ ] **AI Threat explicit domain tag**
  - Add `ai_threat` to the domain taxonomy to capture AI-assisted malware/automation, LLM/model exploitation (prompt injection, data poisoning), and AI infrastructure targets (GPU clusters, training pipelines, model API gateways).
  - Surface as a node in the constellation map and as a KPI in the weekly scope.
  - Scope: new entry in `_TAXONOMY` in `scoring.py`; new edges in `_TM_EDGES`; Groq prompt updated to classify into this domain.

- [ ] **Threat heatmap calendar**
  - GitHub-style contribution calendar below the 7-day history section — one cell per day, color intensity driven by peak risk score or finding count for that day.
  - Makes the passive-monitor check-in instant: glance at the calendar to see which days were hot without expanding the accordion.
  - Scope: computed from `history_days` in `_write_index_html`; pure HTML/CSS/SVG, no new data needed.

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
