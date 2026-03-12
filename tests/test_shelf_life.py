"""
Tests for shelf life (agent.runner._update_shelf) and seen-hash TTL
(agent.state._purge_seen_ttl, agent.state.load_seen, agent.state.save_seen).

Strategy
--------
- _update_shelf reads/writes FINDING_SHELF_FILE (a module-level constant).
  We monkeypatch that constant to a tmp_path file so no real state/ dir is
  touched and tests remain hermetic.
- freezegun.freeze_time pins datetime.now() so multi-day scenario tests
  are deterministic.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from freezegun import freeze_time

import agent.runner as runner_mod
from agent.runner import _update_shelf
from agent.state import _purge_seen_ttl, load_seen, save_seen

pytestmark = pytest.mark.unit


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _card(title="Test Finding", score=50, cid=None):
    return {
        "id": cid or title[:16].replace(" ", "_"),
        "title": title,
        "risk_score": score,
    }


# ─────────────────────────────────────────────────────────────────────────────
# _update_shelf
# ─────────────────────────────────────────────────────────────────────────────


class TestUpdateShelf:
    @pytest.fixture(autouse=True)
    def patch_shelf_file(self, tmp_path, monkeypatch):
        self.shelf_path = str(tmp_path / "finding_shelf.json")
        monkeypatch.setattr(runner_mod, "FINDING_SHELF_FILE", self.shelf_path)

    # ── First-ever run ────────────────────────────────────────────────────────

    @freeze_time("2026-03-10")
    def test_first_run_sets_run_count_1(self):
        card = _card(cid="card_abc")
        _update_shelf([card])
        assert card["run_count"] == 1

    @freeze_time("2026-03-10")
    def test_first_run_no_score_boost(self):
        card = _card(score=60, cid="card_abc")
        _update_shelf([card])
        assert card["risk_score"] == 60  # boost = (1-1)*5 = 0

    @freeze_time("2026-03-10")
    def test_first_run_shelf_days_is_zero(self):
        card = _card(cid="card_abc")
        _update_shelf([card])
        assert card["shelf_days"] == 0

    # ── Second run (same day) ─────────────────────────────────────────────────

    @freeze_time("2026-03-10")
    def test_same_day_second_call_does_not_increment_run_count(self):
        card = _card(cid="card_same")
        _update_shelf([card])
        card2 = _card(cid="card_same")
        _update_shelf([card2])
        assert card2["run_count"] == 1

    # ── Second run (next day) ─────────────────────────────────────────────────

    def test_next_day_increments_run_count_and_applies_boost(self, tmp_path):
        card_day1 = _card(score=50, cid="card_nd")
        with freeze_time("2026-03-10"):
            _update_shelf([card_day1])

        card_day2 = _card(score=50, cid="card_nd")
        with freeze_time("2026-03-11"):
            _update_shelf([card_day2])

        assert card_day2["run_count"] == 2
        assert card_day2["risk_score"] == 55  # 50 + (2-1)*5

    # ── Score boost cap at +20 ────────────────────────────────────────────────

    def test_score_boost_capped_at_20(self):
        """5 runs on 5 separate days: boost should be min(20, (5-1)*5)=20."""
        base_score = 60
        dates = [
            "2026-03-10",
            "2026-03-11",
            "2026-03-12",
            "2026-03-13",
            "2026-03-14",
        ]
        for d in dates:
            with freeze_time(d):
                card = _card(score=base_score, cid="card_cap")
                _update_shelf([card])

        assert card["run_count"] == 5
        assert card["risk_score"] == base_score + 20

    # ── Score never exceeds 100 ───────────────────────────────────────────────

    def test_score_clamped_to_100_after_boost(self):
        """A card with risk_score=95 after 5 runs should never exceed 100."""
        dates = [
            "2026-03-10",
            "2026-03-11",
            "2026-03-12",
            "2026-03-13",
            "2026-03-14",
        ]
        for d in dates:
            with freeze_time(d):
                card = _card(score=95, cid="card_clamp")
                _update_shelf([card])

        assert card["risk_score"] == 100

    # ── 30-day pruning ────────────────────────────────────────────────────────

    def test_stale_entries_pruned_after_30_days(self):
        with freeze_time("2026-02-01"):
            old_card = _card(cid="card_old")
            _update_shelf([old_card])

        with freeze_time("2026-03-15"):  # 42 days later
            new_card = _card(cid="card_new")
            _update_shelf([new_card])

        shelf = json.loads(open(self.shelf_path).read())
        assert "card_old" not in shelf
        assert "card_new" in shelf

    # ── Non-dict cards are skipped ────────────────────────────────────────────

    @freeze_time("2026-03-10")
    def test_non_dict_card_skipped(self):
        good = _card(cid="card_good")
        _update_shelf(["not-a-dict", good])
        assert good["run_count"] == 1  # good card still processed

    # ── shelf_days is correct across calendar days ────────────────────────────

    def test_shelf_days_reflects_real_age(self):
        with freeze_time("2026-03-01"):
            _update_shelf([_card(cid="card_age")])

        with freeze_time("2026-03-10"):
            card = _card(cid="card_age")
            _update_shelf([card])

        assert card["shelf_days"] == 9

    # ── Empty card list is a no-op ────────────────────────────────────────────

    @freeze_time("2026-03-10")
    def test_empty_cards_list(self):
        _update_shelf([])  # Should not raise
        shelf = json.loads(open(self.shelf_path).read()) if os.path.exists(self.shelf_path) else {}
        assert shelf == {}


# ─────────────────────────────────────────────────────────────────────────────
# _purge_seen_ttl (agent.state)
# ─────────────────────────────────────────────────────────────────────────────


class TestPurgeSeenTtl:
    """_purge_seen_ttl in state.py accepts a dict (v2 schema) or a set (v1)."""

    def _past_iso(self, days_ago: int) -> str:
        dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
        return dt.isoformat()

    def _recent_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Dict mode ─────────────────────────────────────────────────────────────

    def test_dict_mode_recent_entries_kept(self):
        seen = {"hash_a": self._recent_iso(), "hash_b": self._recent_iso()}
        result = _purge_seen_ttl(seen, ttl_days=7)
        assert "hash_a" in result
        assert "hash_b" in result

    def test_dict_mode_expired_entries_removed(self):
        seen = {
            "hash_old": self._past_iso(30),   # 30 days old — well past TTL
            "hash_new": self._recent_iso(),
        }
        result = _purge_seen_ttl(seen, ttl_days=7)
        assert "hash_old" not in result
        assert "hash_new" in result

    def test_dict_mode_returns_dict(self):
        seen = {"x": self._recent_iso()}
        result = _purge_seen_ttl(seen, ttl_days=7)
        assert isinstance(result, dict)

    def test_dict_mode_caps_at_max_size(self):
        """With ttl_days=1, max_size = 1 * 2000 = 2000. Create 2500 entries."""
        import agent.state as state_mod
        seen = {f"h{i}": self._recent_iso() for i in range(2500)}
        with pytest.MonkeyPatch().context() as mp:
            mp.setitem(state_mod.CONFIG.setdefault("budgets", {}), "seen_ttl_days", 1)
            result = _purge_seen_ttl(seen, ttl_days=1)
        assert len(result) <= 2000

    def test_dict_mode_invalid_timestamp_kept(self):
        """Entries with unparseable timestamps should be kept, not dropped."""
        seen = {"hash_bad_ts": "not-a-date", "hash_ok": self._recent_iso()}
        result = _purge_seen_ttl(seen, ttl_days=7)
        assert "hash_bad_ts" in result

    def test_empty_dict_returns_empty_dict(self):
        assert _purge_seen_ttl({}, ttl_days=7) == {}

    # ── Set / legacy mode ─────────────────────────────────────────────────────

    def test_set_mode_small_set_unchanged(self):
        seen = {"a", "b", "c"}
        result = _purge_seen_ttl(seen, ttl_days=7)
        assert result == seen

    def test_set_mode_large_set_capped(self):
        import agent.state as state_mod
        seen = {f"h{i}" for i in range(20_000)}
        with pytest.MonkeyPatch().context() as mp:
            mp.setitem(state_mod.CONFIG.setdefault("budgets", {}), "seen_ttl_days", 1)
            result = _purge_seen_ttl(seen, ttl_days=1)  # max_size = 2000
        assert len(result) <= 2000

    def test_set_mode_returns_set(self):
        result = _purge_seen_ttl({"x", "y"}, ttl_days=7)
        assert isinstance(result, set)


# ─────────────────────────────────────────────────────────────────────────────
# load_seen / save_seen round-trip (agent.state)
# ─────────────────────────────────────────────────────────────────────────────


class TestSeenRoundTrip:
    def test_roundtrip_dict_schema(self, tmp_path):
        path = str(tmp_path / "seen.json")
        now = datetime.now(timezone.utc).isoformat()
        seen_in = {"hash_a": now, "hash_b": now}
        save_seen(path, seen_in)
        seen_out = load_seen(path)
        assert "hash_a" in seen_out
        assert "hash_b" in seen_out

    def test_missing_file_returns_empty_dict(self, tmp_path):
        path = str(tmp_path / "nonexistent.json")
        result = load_seen(path)
        assert isinstance(result, dict)
        assert len(result) == 0

    def test_legacy_hashes_list_upgraded_on_load(self, tmp_path):
        """Old {"hashes": [...]} schema should be transparently upgraded to dict."""
        path = str(tmp_path / "seen_legacy.json")
        with open(path, "w") as f:
            json.dump({"hashes": ["abc123", "def456"]}, f)
        result = load_seen(path)
        assert isinstance(result, dict)
        assert "abc123" in result
        assert "def456" in result

    def test_save_creates_version_2_key(self, tmp_path):
        path = str(tmp_path / "seen.json")
        now = datetime.now(timezone.utc).isoformat()
        save_seen(path, {"h1": now})
        raw = json.loads(open(path).read())
        assert raw.get("version") == 2

    def test_empty_seen_dict_saves_and_loads(self, tmp_path):
        path = str(tmp_path / "seen_empty.json")
        save_seen(path, {})
        result = load_seen(path)
        assert result == {}
