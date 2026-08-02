"""Client for re.session.* tools — talk to session_server over TCP JSON lines."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
import uuid
from typing import Any

from easy_rev.platforms.web.re.session_store import (
    delete_session_meta,
    list_session_metas,
    read_session_meta,
    sessions_dir,
    write_session_meta,
)

logger = logging.getLogger(__name__)

# In-process sessions for long-lived hosts (MCP). Keyed by session_id.
_INPROC: dict[str, Any] = {}


async def rpc_call(
    session_id: str,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout_s: float = 120.0,
    token: str | None = None,
) -> dict[str, Any]:
    from easy_rev.platforms.web.re.session_gc import touch_session

    meta = read_session_meta(session_id)
    stored = meta.get("auth_token")
    effective_token = token if token is not None else stored
    if stored and str(effective_token or "") != str(stored):
        raise PermissionError("invalid session auth_token")

    host = meta.get("host") or "127.0.0.1"
    port = int(meta["port"])
    req = {
        "id": uuid.uuid4().hex[:8],
        "method": method,
        "params": params or {},
        "token": effective_token,
    }
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=min(10.0, timeout_s),
        )
    except Exception as e:  # noqa: BLE001
        raise ConnectionError(
            f"cannot connect to session {session_id} at {host}:{port}: {e}"
        ) from e
    try:
        writer.write((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
        if not line:
            raise ConnectionError("session closed without response")
        resp = json.loads(line.decode("utf-8"))
        if not resp.get("ok"):
            err = resp.get("error") or {}
            raise RuntimeError(err.get("message") or str(err))
        touch_session(session_id)
        return resp.get("result") or {}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def session_start(args: dict[str, Any]) -> dict[str, Any]:
    """Spawn session_server subprocess and wait until ready."""
    # Opportunistic GC of stale sessions
    try:
        from easy_rev.platforms.web.re.session_gc import gc_sessions

        await gc_sessions(idle_ttl_s=float(args.get("gc_idle_ttl_s") or 1800), kill=True)
    except Exception:  # noqa: BLE001
        pass

    session_id = str(args.get("session_id") or uuid.uuid4().hex[:12])
    url = args.get("url")
    engine = args.get("engine") or "camoufox"
    if engine == "auto":
        engine = "camoufox"
    headless = bool(args.get("headless", True))
    headed = not headless
    auth_token = str(args.get("auth_token") or uuid.uuid4().hex)
    idle_ttl_s = float(args.get("idle_ttl_s") or 1800)

    ready_file = sessions_dir() / f"{session_id}.ready"
    if ready_file.exists():
        ready_file.unlink()

    # Pre-write starting meta
    write_session_meta(
        session_id,
        {
            "status": "starting",
            "url": url,
            "engine": engine,
            "headless": headless,
            "host": "127.0.0.1",
            "port": 0,
            "pid": None,
            "auth_token": auth_token,
            "started_at": time.time(),
            "last_active": time.time(),
            "idle_ttl_s": idle_ttl_s,
        },
    )

    cdp_url = args.get("cdp_url") or args.get("cdp") or args.get("chrome_cdp")
    if cdp_url:
        engine = "cdp"
    tab_url = args.get("cdp_target_url") or args.get("tab_url") or args.get("target_url")
    tab_index = args.get("cdp_target_index")
    if tab_index is None:
        tab_index = args.get("tab_index")

    cmd = [
        sys.executable,
        "-m",
        "easy_rev.platforms.web.re.session_server",
        "--session-id",
        session_id,
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--engine",
        engine,
        "--ready-file",
        str(ready_file),
        "--auth-token",
        auth_token,
        "--idle-ttl-s",
        str(idle_ttl_s),
    ]
    if url:
        cmd.extend(["--url", str(url)])
    if cdp_url:
        cmd.extend(["--cdp-url", str(cdp_url)])
    if tab_url:
        cmd.extend(["--cdp-target-url", str(tab_url)])
    if tab_index is not None:
        cmd.extend(["--cdp-target-index", str(int(tab_index))])
    if args.get("navigate") is False or (cdp_url and not args.get("navigate", False)):
        cmd.append("--no-navigate")
    if headed:
        cmd.append("--headed")
    else:
        cmd.append("--headless")

    log_path = sessions_dir() / f"{session_id}.log"
    log_f = open(log_path, "w", encoding="utf-8")  # noqa: SIM115
    proc = subprocess.Popen(
        cmd,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    write_session_meta(
        session_id,
        {
            "status": "starting",
            "url": url,
            "engine": engine,
            "headless": headless,
            "host": "127.0.0.1",
            "port": 0,
            "pid": proc.pid,
            "log_path": str(log_path),
            "auth_token": auth_token,
            "started_at": time.time(),
            "last_active": time.time(),
            "idle_ttl_s": idle_ttl_s,
        },
    )

    # Wait for ready (meta port or ready file)
    deadline = time.time() + float(args.get("start_timeout_s") or 60)
    last_err = "timeout waiting for session"
    while time.time() < deadline:
        if proc.poll() is not None:
            log_f.flush()
            tail = ""
            try:
                tail = log_path.read_text(encoding="utf-8")[-2000:]
            except Exception:  # noqa: BLE001
                pass
            delete_session_meta(session_id)
            raise RuntimeError(f"session process exited early code={proc.returncode}: {tail}")
        try:
            meta = read_session_meta(session_id)
            if meta.get("status") == "ready" and meta.get("port"):
                # verify ping
                try:
                    pong = await rpc_call(
                        session_id, "ping", timeout_s=5, token=auth_token
                    )
                    return {
                        "session_id": session_id,
                        "port": meta["port"],
                        "pid": meta.get("pid") or proc.pid,
                        "url": meta.get("url") or url,
                        "engine": engine,
                        "headless": headless,
                        "log_path": str(log_path),
                        "auth_token": auth_token,
                        "idle_ttl_s": idle_ttl_s,
                        "ping": pong,
                    }
                except Exception as e:  # noqa: BLE001
                    last_err = str(e)
        except FileNotFoundError:
            pass
        await asyncio.sleep(0.25)

    # timeout — kill
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:  # noqa: BLE001
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
    raise TimeoutError(last_err)


async def session_stop(session_id: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    try:
        meta = read_session_meta(session_id)
    except FileNotFoundError:
        return {"session_id": session_id, "stopped": False, "reason": "not_found"}

    exported = None
    try:
        exported = await rpc_call(session_id, "export", timeout_s=30)
    except Exception:  # noqa: BLE001
        pass
    try:
        await rpc_call(session_id, "stop", timeout_s=5)
    except Exception:  # noqa: BLE001
        pass

    pid = meta.get("pid")
    if pid:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception:  # noqa: BLE001
            try:
                os.killpg(int(pid), signal.SIGTERM)
            except Exception:  # noqa: BLE001
                pass

    # wait briefly
    await asyncio.sleep(0.3)
    delete_session_meta(session_id)
    return {
        "session_id": session_id,
        "stopped": True,
        "export": exported,
    }


async def session_list() -> dict[str, Any]:
    sessions = []
    for meta in list_session_metas():
        sid = meta.get("session_id")
        alive = False
        if sid and meta.get("port"):
            try:
                await rpc_call(str(sid), "ping", timeout_s=2)
                alive = True
            except Exception:  # noqa: BLE001
                alive = False
        sessions.append({**meta, "alive": alive})
    return {"sessions": sessions}


def is_process_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:  # noqa: BLE001
        return False
