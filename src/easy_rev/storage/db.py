"""Minimal SQLite storage for captures and diagnose lookups."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from easy_rev.core.paths import db_path


class Storage:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or db_path())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS captures (
                  id TEXT PRIMARY KEY,
                  platform TEXT,
                  target TEXT,
                  path TEXT,
                  meta_json TEXT,
                  created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                  id TEXT PRIMARY KEY,
                  kind TEXT,
                  status TEXT,
                  meta_json TEXT,
                  created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def save_capture(
        self,
        capture_id: str,
        *,
        platform: str,
        target: str,
        path: str,
        meta: dict[str, Any] | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO captures (id, platform, target, path, meta_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (capture_id, platform, target, path, json.dumps(meta or {})),
            )

    def get_capture(self, capture_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM captures WHERE id = ?", (capture_id,)
            ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "platform": row["platform"],
            "target": row["target"],
            "path": row["path"],
            "meta": json.loads(row["meta_json"] or "{}"),
            "created_at": row["created_at"],
        }

    def list_captures(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM captures ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "platform": r["platform"],
                "target": r["target"],
                "path": r["path"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Compatibility shim for diagnose_proto (no full job farm yet)."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "meta": json.loads(row["meta_json"] or "{}"),
        }
