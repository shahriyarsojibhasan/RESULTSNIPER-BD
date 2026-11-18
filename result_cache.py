import hashlib
import json
import os
import sqlite3
import threading
import time

CACHE_TTL_SECONDS = 365 * 24 * 60 * 60  # 1 year (365 days)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCAL_DB = os.path.join(_BASE_DIR, "results_cache.sqlite")
_TMP_DB = "/tmp/rs_results_cache.sqlite"
_DB_LOCK = threading.Lock()
_ACTIVE_DB_PATH = None


def _get_db_path():
    global _ACTIVE_DB_PATH
    if _ACTIVE_DB_PATH:
        return _ACTIVE_DB_PATH
    candidates = (_TMP_DB,) if os.environ.get("VERCEL") else (_LOCAL_DB, _TMP_DB)
    for path in candidates:
        try:
            conn = sqlite3.connect(path, timeout=5)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS result_cache (
                    cache_key TEXT PRIMARY KEY,
                    engine TEXT NOT NULL,
                    exam TEXT NOT NULL,
                    year TEXT NOT NULL,
                    board TEXT NOT NULL,
                    roll TEXT NOT NULL,
                    has_marks INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    cached_at INTEGER NOT NULL
                )
                """
            )
            conn.commit()
            conn.close()
            _ACTIVE_DB_PATH = path
            return path
        except Exception:
            continue
    return None


def _norm_board_slug(board):
    s = str(board or "").strip().lower()
    aliases = {
        "cumilla": "comilla",
        "chattogram": "chittagong",
        "jashore": "jessore",
        "barishal": "barisal",
        "bteb": "technical",
        "tec": "technical",
        "madrasa": "madrasah",
    }
    return aliases.get(s, s or "dhaka")


def make_cache_key(engine, exam, year, board, roll, reg):
    """Build deterministic SHA-256 cache key bound to roll + reg."""
    parts = (
        str(engine or "").strip().lower(),
        str(exam or "").strip().lower(),
        str(year or "").strip(),
        _norm_board_slug(board),
        str(roll or "").strip(),
        str(reg or "").strip(),
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _blob_path(cache_key):
    return f"rs_cache/{cache_key}.json"


def _blob_read(cache_key):
    if not os.environ.get("BLOB_READ_WRITE_TOKEN"):
        return None
    try:
        from vercel.blob import sync as vblob

        res = vblob.get_blob(_blob_path(cache_key), access="private")
        raw = res.body.decode("utf-8") if isinstance(res.body, (bytes, bytearray)) else str(res.body)
        return json.loads(raw)
    except Exception:
        return None


def _blob_write(cache_key, envelope):
    if not os.environ.get("BLOB_READ_WRITE_TOKEN"):
        return False
    try:
        from vercel.blob import sync as vblob

        raw = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        vblob.put_blob(
            _blob_path(cache_key),
            raw,
            access="private",
            content_type="application/json",
            add_random_suffix=False,
            allow_overwrite=True,
        )
        return True
    except Exception:
        return False


def _sqlite_get(cache_key):
    db_path = _get_db_path()
    if not db_path:
        return None
    try:
        with _DB_LOCK:
            conn = sqlite3.connect(db_path, timeout=5)
            row = conn.execute(
                "SELECT payload_json, cached_at FROM result_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
            conn.close()
        if not row:
            return None
        payload = json.loads(row[0])
        return {"payload": payload, "cached_at": int(row[1])}
    except Exception:
        return None


def _sqlite_put(cache_key, engine, exam, year, board, roll, has_marks, payload, cached_at):
    db_path = _get_db_path()
    if not db_path:
        return False
    try:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with _DB_LOCK:
            conn = sqlite3.connect(db_path, timeout=5)
            conn.execute(
                """
                INSERT INTO result_cache (cache_key, engine, exam, year, board, roll, has_marks, payload_json, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    has_marks=excluded.has_marks,
                    payload_json=excluded.payload_json,
                    cached_at=excluded.cached_at
                """,
                (cache_key, engine, exam, year, _norm_board_slug(board), roll, int(bool(has_marks)), raw, cached_at),
            )
            conn.commit()
            conn.close()
        return True
    except Exception:
        return False


def store_cached_result(engine, exam, year, board, roll, reg, data):
    """Persist a verified board result for 1 year when Registration No. is known."""
    roll_s = str(roll or "").strip()
    reg_s = str(reg or data.get("reg") or "").strip()
    if not roll_s or not reg_s or reg_s.upper() in ("N/A", "[NOT SHOWN]", "NOT SHOWN", "--"):
        return False

    # Do not store dynamic token/doc_id strings as stale; re-sign cleanly on cache retrieval.
    clean_data = dict(data)
    clean_data.pop("verify_token", None)
    clean_data.pop("doc_id", None)
    has_marks = any(str(s.get("total", s.get("marks", ""))).strip().isdigit() for s in clean_data.get("subjects", []))
    now = int(time.time())
    key = make_cache_key(engine, exam, year, board, roll_s, reg_s)

    _sqlite_put(key, str(engine).lower(), str(exam).lower(), str(year), board, roll_s, has_marks, clean_data, now)
    _blob_write(key, {"payload": clean_data, "cached_at": now, "engine": engine})
    return True


def lookup_cached_result(exam, year, board, roll, reg, preferred_engine=None):
    """Retrieve a non-expired (< 1 year) cached result matching Roll + Registration."""
    roll_s = str(roll or "").strip()
    reg_s = str(reg or "").strip()
    if not roll_s or not reg_s:
        return None

    engines = ["eduboard", "eboard"]
    if preferred_engine == "eboard":
        engines = ["eboard", "eduboard"]

    now = int(time.time())
    for eng in engines:
        key = make_cache_key(eng, exam, year, board, roll_s, reg_s)
        entry = _sqlite_get(key)
        if not entry:
            entry = _blob_read(key)
            if entry and isinstance(entry.get("payload"), dict):
                _sqlite_put(
                    key,
                    eng,
                    str(exam).lower(),
                    str(year),
                    board,
                    roll_s,
                    1,
                    entry["payload"],
                    int(entry.get("cached_at", now)),
                )
        if entry and isinstance(entry.get("payload"), dict):
            age = now - int(entry.get("cached_at", 0))
            if 0 <= age < CACHE_TTL_SECONDS:
                data = dict(entry["payload"])
                data["cache_hit"] = True
                data["cached_at"] = int(entry.get("cached_at", now))
                return data
    return None


def cache_stats():
    """Return aggregate non-PII cache metrics for diagnostics/health checks."""
    db_path = _get_db_path()
    count = 0
    if db_path:
        try:
            cutoff = int(time.time()) - CACHE_TTL_SECONDS
            with _DB_LOCK:
                conn = sqlite3.connect(db_path, timeout=5)
                row = conn.execute("SELECT COUNT(*) FROM result_cache WHERE cached_at > ?", (cutoff,)).fetchone()
                conn.close()
                count = int(row[0]) if row else 0
        except Exception:
            pass
    return {
        "local_entries": count,
        "cloud_blob_enabled": bool(os.environ.get("BLOB_READ_WRITE_TOKEN")),
        "ttl_days": 365,
    }
