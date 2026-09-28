"""SQLite persistence: assets, immutable snapshots, diff events with dedup."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .normalize import attr_hash, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    key TEXT PRIMARY KEY, kind TEXT, attrs_json TEXT,
    sources_json TEXT, first_seen TEXT, last_seen TEXT, confidence INTEGER
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT, ts TEXT,
    asset_count INTEGER, provider_mask TEXT
);
CREATE TABLE IF NOT EXISTS snapshot_assets (
    snap_id INTEGER, asset_key TEXT, attr_hash TEXT, kind TEXT, attrs_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_snap_assets ON snapshot_assets(snap_id);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT, kind TEXT, asset_key TEXT,
    detail_json TEXT, severity REAL, techniques TEXT, kev_cves TEXT,
    created_at TEXT, dedup_key TEXT UNIQUE
);
"""


class Store:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    # ------------------------------------------------ assets
    def upsert_assets(self, assets: list[dict]):
        for a in assets:
            cur = self.conn.execute("SELECT sources_json, first_seen FROM assets WHERE key=?",
                                    (a["key"],))
            row = cur.fetchone()
            if row:
                old_sources = set(json.loads(row["sources_json"]))
                new_sources = sorted(old_sources | set(a["sources"]))
                self.conn.execute(
                    "UPDATE assets SET attrs_json=?, sources_json=?, last_seen=?, "
                    "confidence=?, kind=? WHERE key=?",
                    (json.dumps(a["attrs"], default=str), json.dumps(new_sources),
                     a["last_seen"], a["confidence"], a["kind"], a["key"]))
            else:
                self.conn.execute(
                    "INSERT INTO assets(key,kind,attrs_json,sources_json,first_seen,"
                    "last_seen,confidence) VALUES(?,?,?,?,?,?,?)",
                    (a["key"], a["kind"], json.dumps(a["attrs"], default=str),
                     json.dumps(a["sources"]), a["first_seen"], a["last_seen"],
                     a["confidence"]))

    # ------------------------------------------------ snapshots
    def write_snapshot(self, scope: str, assets: list[dict], mask: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO snapshots(scope,ts,asset_count,provider_mask) VALUES(?,?,?,?)",
            (scope, utcnow(), len(assets), mask))
        snap_id = cur.lastrowid
        self.conn.executemany(
            "INSERT INTO snapshot_assets(snap_id,asset_key,attr_hash,kind,attrs_json) "
            "VALUES(?,?,?,?,?)",
            [(snap_id, a["key"], attr_hash(a["attrs"]), a["kind"],
              json.dumps(a["attrs"], default=str)) for a in assets])
        self.conn.commit()
        return snap_id

    def latest_snapshots(self, scope: str, n: int = 2) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM snapshots WHERE scope=? ORDER BY id DESC LIMIT ?",
            (scope, n)))

    def snapshot_map(self, snap_id: int) -> dict[str, dict]:
        """asset_key -> {hash, kind, attrs}"""
        return {r["asset_key"]: {"hash": r["attr_hash"], "kind": r["kind"],
                                 "attrs": json.loads(r["attrs_json"] or "{}")}
                for r in self.conn.execute(
                    "SELECT asset_key, attr_hash, kind, attrs_json FROM snapshot_assets "
                    "WHERE snap_id=?", (snap_id,))}

    def asset(self, key: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM assets WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        return {"key": row["key"], "kind": row["kind"],
                "attrs": json.loads(row["attrs_json"]),
                "sources": json.loads(row["sources_json"]),
                "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                "confidence": row["confidence"]}

    def attr_history(self, scope: str, asset_key: str, scans: int = 5,
                     exclude_snap: int | None = None) -> list[dict]:
        """Recent historical attrs (oldest→newest) for one asset, from the
        last `scans` snapshots of a scope — used for rotation-noise memory.
        `exclude_snap` must be the current snapshot id, else history compares
        the new value against itself."""
        q = ("SELECT sa.attrs_json, sa.snap_id FROM snapshot_assets sa JOIN snapshots s "
             "ON sa.snap_id = s.id WHERE s.scope=? AND sa.asset_key=? ")
        args: list = [scope, asset_key]
        if exclude_snap is not None:
            q += "AND sa.snap_id < ? "
            args.append(exclude_snap)
        q += "ORDER BY s.id DESC LIMIT ?"
        args.append(scans)
        rows = list(self.conn.execute(q, args))
        out = []
        for r in reversed(rows):
            try:
                a = json.loads(r["attrs_json"] or "{}")
                out.append(set(map(str, a.get("a") or [])))
            except Exception:
                continue
        return out

    # ------------------------------------------------ events
    def insert_event(self, scope: str, kind: str, asset_key: str, detail: dict,
                     severity: float, techniques: list[str], kev_cves: list[str]) -> bool:
        dedup = f"{scope}|{kind}|{asset_key}|{detail.get('material', '')}"
        try:
            self.conn.execute(
                "INSERT INTO events(scope,kind,asset_key,detail_json,severity,techniques,"
                "kev_cves,created_at,dedup_key) VALUES(?,?,?,?,?,?,?,?,?)",
                (scope, kind, asset_key, json.dumps(detail, default=str), severity,
                 json.dumps(techniques), json.dumps(kev_cves), utcnow(), dedup))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate — already alerted

    def events(self, scope: str | None = None, since: str | None = None) -> list[dict]:
        q = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if scope:
            q += " AND scope=?"; args.append(scope)
        if since:
            q += " AND created_at >= ?"; args.append(since)
        q += " ORDER BY severity DESC, id DESC"
        return [dict(r) for r in self.conn.execute(q, args)]
