"""Paths and metadata for reverse-engineering browser sessions."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from easy_rev.core.paths import data_dir


def sessions_dir() -> Path:
    p = data_dir() / "re_sessions"
    p.mkdir(parents=True, exist_ok=True)
    return p


def session_meta_path(session_id: str) -> Path:
    return sessions_dir() / f"{session_id}.json"


def write_session_meta(session_id: str, meta: dict[str, Any]) -> Path:
    path = session_meta_path(session_id)
    meta = {**meta, "session_id": session_id, "updated_at": time.time()}
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path


def read_session_meta(session_id: str) -> dict[str, Any]:
    path = session_meta_path(session_id)
    if not path.exists():
        raise FileNotFoundError(f"session not found: {session_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_session_metas() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in sorted(sessions_dir().glob("*.json")):
        if p.name.endswith(".log.json"):
            continue
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
    return out


def delete_session_meta(session_id: str) -> None:
    path = session_meta_path(session_id)
    if path.exists():
        path.unlink()
