# Watchtower — Agentic InfraSec Monitor (GitHub-only)

This implementation follows your spec and defaults to a **free/local-safe placeholder mode** for development.

## What is implemented now
- GitHub Actions schedule + NY-hour gate + concurrency + optional Pages deployment.
- Python runtime with:
  - feed polling (RSS + NVD JSON API + CISA KEV JSON)
  - strict URL/content safety checks
  - run-to-run dedup (`state/seen_hashes.json`)
  - clustering + risk scoring
  - domain heat map + ranked findings UI (`reports/index.html`)
  - append-only run ledger (`state/ledger.jsonl`)
- Planner integration with Groq when enabled.
- **Placeholder mode** (default local) to avoid paid/external API dependence while building.

## Modes
### 1) Local demo (default)
- `WATCHTOWER_PLACEHOLDER_MODE=true` (default)
- No external API requirement
- Generates lightweight UI with sample findings

### 2) Real mode (CI/production)
- Set `WATCHTOWER_PLACEHOLDER_MODE=false`
- Provide `GROQ_API_KEY` secret
- Optional: `NVD_API_KEY` for higher NVD rate limits

## Quick start
1. Create virtual env and install deps from [requirements.txt](requirements.txt)
2. Run `python agent/runner.py`
3. Open [reports/index.html](reports/index.html)

## Missing parts / next recommended hardening
- Add signed provenance (e.g., attestations/SBOM) for workflow outputs.
- Add allowlist for outbound domains in runtime, not only scheme/private-network checks.
- Add unit tests for `poll_feed`, scoring, and planner dispatch.
- Add retention policy/rotation for old `reports/briefing_*.md|jsonl` artifacts.
- Add stricter HTML escaping for link/title rendering before writing UI.
- Add optional local mock server fixtures for deterministic CI tests.

## Notes
- In real mode, missing `GROQ_API_KEY` raises `RuntimeError` by design.
- Cron schedules are UTC; workflow runtime gate enforces NY windows `{0,6,12,18}`.
