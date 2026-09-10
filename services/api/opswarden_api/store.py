"""Durable proposal + audit store (SQLite). Separate from the LangGraph checkpointer so the
audit page can list everything the agent has ever done, independent of graph internals."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta

_lock = threading.Lock()


class Store:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS proposals ("
            " id TEXT PRIMARY KEY, ticket TEXT, status TEXT, created TEXT, doc TEXT)")
        self._db.commit()

    def upsert(self, doc: dict) -> None:
        with _lock:
            self._db.execute(
                "INSERT INTO proposals (id, ticket, status, created, doc) VALUES (?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET ticket=excluded.ticket, status=excluded.status, "
                "doc=excluded.doc",
                (doc["id"], doc.get("ticket_number"), doc.get("status"),
                 doc.get("created_at", datetime.now(UTC).isoformat()),
                 json.dumps(doc, default=str)))
            self._db.commit()

    def get(self, pid: str) -> dict | None:
        row = self._db.execute("SELECT doc FROM proposals WHERE id=?", (pid,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, limit: int = 100) -> list[dict]:
        rows = self._db.execute(
            "SELECT doc FROM proposals ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def find_open_duplicate(self, dedup_key: str, within_minutes: int) -> dict | None:
        """An event already awaiting approval for the same target is a repeat, not news."""
        if not dedup_key:
            return None
        cutoff = datetime.now(UTC) - timedelta(minutes=within_minutes)
        rows = self._db.execute(
            "SELECT doc FROM proposals WHERE status='awaiting_approval' "
            "ORDER BY created DESC LIMIT 200").fetchall()
        for (raw,) in rows:
            doc = json.loads(raw)
            if doc.get("dedup_key") != dedup_key:
                continue
            try:
                created = datetime.fromisoformat(doc.get("created_at", ""))
            except ValueError:
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            if created >= cutoff:
                return doc
        return None

    def set_status(self, pid: str, status: str) -> None:
        doc = self.get(pid)
        if doc:
            doc["status"] = status
            self.upsert(doc)

    def delete(self, pid: str) -> None:
        with _lock:
            self._db.execute("DELETE FROM proposals WHERE id=?", (pid,))
            self._db.commit()

    def append_audit(self, pid: str, entry: str) -> None:
        doc = self.get(pid)
        if not doc:
            return
        doc.setdefault("audit", []).append(
            {"at": datetime.now(UTC).isoformat(), "entry": entry})
        self.upsert(doc)
