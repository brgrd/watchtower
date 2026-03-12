"""State, persistence, and history helpers for Watchtower."""

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import yaml

ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG = yaml.safe_load(
    open(os.path.join(ROOT, "agent", "config.yaml"), "r", encoding="utf-8")
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return default


def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def append_jsonl(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _extract_cves(s: str) -> list:
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(s or "")})


def load_seen(seen_file: str) -> set:
    d = load_json(seen_file, {"hashes": []})
    seen_map = d.get("seen")
    if isinstance(seen_map, dict):
        return {str(k): str(v) for k, v in seen_map.items() if k}

    # Backward compatibility with legacy {"hashes": [...]} schema.
    hashes = [str(h) for h in d.get("hashes", []) if h]
    ts = now_utc_iso()
    return {h: ts for h in hashes}


def _purge_seen_ttl(seen: set, ttl_days: int = 7) -> set:
    ttl_cap = CONFIG.get("budgets", {}).get("seen_ttl_days", ttl_days)
    max_size = ttl_cap * 2000
    if isinstance(seen, dict):
        cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_cap)

        def _parse_ts(ts: str):
            try:
                return datetime.fromisoformat(str(ts))
            except Exception:
                return None

        rows = []
        for h, ts in seen.items():
            dt = _parse_ts(ts)
            if dt is not None and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt is not None and dt < cutoff:
                continue
            # Invalid timestamps are kept but rank as oldest deterministically.
            order_ts = dt or datetime.min.replace(tzinfo=timezone.utc)
            rows.append((str(h), str(ts), order_ts))

        # Deterministic ordering: oldest -> newest, then hash.
        rows.sort(key=lambda x: (x[2], x[0]))
        if len(rows) > max_size:
            rows = rows[-max_size:]
        return {h: ts for h, ts, _ in rows}

    if len(seen) > max_size:
        # Deterministic fallback for legacy set callers.
        return set(sorted(seen)[-max_size:])
    return seen


def save_seen(seen_file: str, seen: set):
    seen = _purge_seen_ttl(seen)
    if isinstance(seen, dict):
        keys_sorted = sorted(seen.keys())
        if len(keys_sorted) > 50_000:
            keys_sorted = keys_sorted[-50_000:]
        seen_trimmed = {k: seen[k] for k in keys_sorted}
        save_json(
            seen_file,
            {
                "version": 2,
                "seen": seen_trimmed,
                "hashes": keys_sorted,
            },
        )
        return

    keys_sorted = sorted(seen)
    if len(keys_sorted) > 50_000:
        keys_sorted = keys_sorted[-50_000:]
    save_json(seen_file, {"version": 1, "hashes": keys_sorted})


def item_hash(item: dict) -> str:
    return sha256(item.get("url", "") + item.get("title", ""))


def deduplicate(items: list, seen: set):
    fresh = []
    if isinstance(seen, dict):
        ts = now_utc_iso()
        for it in items:
            h = item_hash(it)
            if h in seen:
                # Refresh recency for deterministic pruning.
                seen[h] = ts
                continue
            seen[h] = ts
            fresh.append(it)
        return fresh, seen

    for it in items:
        h = item_hash(it)
        if h in seen:
            continue
        seen.add(h)
        fresh.append(it)
    return fresh, seen


def _read_ledger_history(ledger_file: str, n: int = 20) -> list:
    if not os.path.exists(ledger_file):
        return []
    entries = []
    with open(ledger_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
                if "error" not in obj and "counts" in obj:
                    entries.append(obj)
            except Exception:
                pass
    return entries[-n:]


def _prune_old_briefings(reports_dir: str, keep_days: int = 10) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    if not os.path.isdir(reports_dir):
        return
    for fname in os.listdir(reports_dir):
        if not fname.startswith("briefing_"):
            continue
        if not (fname.endswith(".jsonl") or fname.endswith(".md")):
            continue
        ext = ".jsonl" if fname.endswith(".jsonl") else ".md"
        stem = fname[len("briefing_") : -len(ext)]
        try:
            dt = datetime.strptime(stem, "%Y-%m-%d_%H-%M").replace(tzinfo=timezone.utc)
            if dt < cutoff:
                os.remove(os.path.join(reports_dir, fname))
        except Exception:
            pass


def _load_history_days(reports_dir: str, n: int = 7) -> list:
    try:
        et_tz = ZoneInfo("America/New_York")
    except Exception:
        # Fallback for environments lacking system tzdata (e.g., minimal Windows Python installs).
        et_tz = timezone(timedelta(hours=-5))
    runs: list = []
    if not os.path.isdir(reports_dir):
        return []
    for fname in os.listdir(reports_dir):
        if not (fname.startswith("briefing_") and fname.endswith(".jsonl")):
            continue
        stem = fname[len("briefing_") : -len(".jsonl")]
        try:
            dt = datetime.strptime(stem, "%Y-%m-%d_%H-%M").replace(tzinfo=timezone.utc)
            runs.append((dt, os.path.join(reports_dir, fname)))
        except Exception:
            pass
    days_map: dict = {}
    for dt, fp in runs:
        et_date = dt.astimezone(et_tz).strftime("%Y-%m-%d")
        existing = days_map.get(et_date)
        if existing is None or dt > existing[0]:
            days_map[et_date] = (dt, fp)
    sorted_dates = sorted(days_map.keys(), reverse=True)[:n]
    result = []
    for date_str in sorted_dates:
        dt, fp = days_map[date_str]
        cards: list = []
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        cards.append(json.loads(line.strip()))
                    except Exception:
                        pass
        except Exception:
            pass
        result.append(
            {
                "date_str": date_str,
                "ts_str": dt.strftime("%Y-%m-%d %H:%M UTC"),
                "cards": cards,
            }
        )
    return result


def _rebuild_weekly_aggregate(
    reports_dir: str,
    weekly_aggregate_file: str,
    days: list = None,
) -> dict:
    if days is None:
        days = _load_history_days(reports_dir, n=7)
    cve_counts: dict = {}
    domain_set: set = set()
    total_cards = 0
    day_counts: dict = {}
    for day in days:
        date_str = day["date_str"]
        cards = day["cards"]
        total_cards += len(cards)
        day_counts[date_str] = len(cards)
        for c in cards:
            raw = c.get("title", "") + " " + c.get("summary", "")
            for cve in _extract_cves(raw):
                cve_counts[cve] = cve_counts.get(cve, 0) + 1
            for d in c.get("domains", []):
                if d and d != "uncategorised":
                    domain_set.add(d)
    top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    most_active_day = max(day_counts, key=lambda k: day_counts[k]) if day_counts else ""
    existing = load_json(weekly_aggregate_file, {})
    return {
        "rebuilt_at": now_utc_iso(),
        "window_days": len(days),
        "total_cards": total_cards,
        "unique_cves": len(cve_counts),
        "active_domains": sorted(domain_set),
        "most_active_day": most_active_day,
        "day_counts": day_counts,
        "top_cves": [{"cve": k, "count": v} for k, v in top_cves],
        "weekly_summary": existing.get("weekly_summary", ""),
        "weekly_summary_ts": existing.get("weekly_summary_ts", ""),
    }
