"""Session lifecycle: GC dead sessions, idle TTL, auth tokens."""

from __future__ import annotations

import logging
import os
import signal
import time
from typing import Any

from easy_rev.platforms.web.re.session_store import (
    delete_session_meta,
    list_session_metas,
    read_session_meta,
    write_session_meta,
)

logger = logging.getLogger(__name__)

DEFAULT_IDLE_TTL_S = 30 * 60  # 30 minutes
DEFAULT_MAX_AGE_S = 4 * 60 * 60  # 4 hours


def is_pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:  # noqa: BLE001
        return False


async def gc_sessions(
    *,
    idle_ttl_s: float = DEFAULT_IDLE_TTL_S,
    max_age_s: float = DEFAULT_MAX_AGE_S,
    kill: bool = True,
) -> dict[str, Any]:
    """Stop dead/idle/expired RE sessions and delete meta."""
    from easy_rev.platforms.web.re.session_client import rpc_call, session_stop

    now = time.time()
    report: list[dict[str, Any]] = []
    for meta in list_session_metas():
        sid = str(meta.get("session_id") or "")
        if not sid:
            continue
        pid = meta.get("pid")
        started = float(meta.get("started_at") or meta.get("updated_at") or 0)
        last = float(meta.get("last_active") or meta.get("updated_at") or started or now)
        reason = None
        alive_rpc = False
        if meta.get("port"):
            try:
                await rpc_call(sid, "ping", timeout_s=2)
                alive_rpc = True
                # touch last_active on successful ping is server-side; client updates:
                meta["last_active"] = now
                write_session_meta(sid, {**meta, "last_active": now, "status": "ready"})
            except Exception:  # noqa: BLE001
                alive_rpc = False

        if not alive_rpc and not is_pid_alive(pid):
            reason = "dead"
        elif max_age_s > 0 and started and (now - started) > max_age_s:
            reason = "max_age"
        elif idle_ttl_s > 0 and last and (now - last) > idle_ttl_s:
            reason = "idle_ttl"

        if reason:
            stopped = False
            if kill:
                try:
                    await session_stop(sid)
                    stopped = True
                except Exception:  # noqa: BLE001
                    try:
                        if pid:
                            os.kill(int(pid), signal.SIGTERM)
                    except Exception:  # noqa: BLE001
                        pass
                    delete_session_meta(sid)
            else:
                delete_session_meta(sid)
            report.append({"session_id": sid, "reason": reason, "stopped": stopped or True})
    return {"gc": report, "count": len(report), "idle_ttl_s": idle_ttl_s, "max_age_s": max_age_s}


def touch_session(session_id: str) -> None:
    try:
        meta = read_session_meta(session_id)
        meta["last_active"] = time.time()
        write_session_meta(session_id, meta)
    except Exception:  # noqa: BLE001
        pass


def verify_session_token(session_id: str, token: str | None) -> bool:
    """If session has auth_token set, require matching token."""
    try:
        meta = read_session_meta(session_id)
    except FileNotFoundError:
        return False
    expected = meta.get("auth_token")
    if not expected:
        return True
    return bool(token) and str(token) == str(expected)
