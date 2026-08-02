"""In-process Frida live sessions with normalized message schema.

Works for desktop (process attach) and mobile (package spawn/attach).
Without frida installed, start() returns dry_run status and still registers a stub session.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from easy_rev.core.paths import artifacts_dir
from easy_rev.core.result import dynamic_result

Kind = Literal["desktop", "mobile"]


def normalize_frida_message(raw: dict[str, Any] | None, *, data_len: int | None = None) -> dict[str, Any]:
    """Normalize Frida on_message payload into a stable schema."""
    raw = raw or {}
    mtype = raw.get("type") or "unknown"
    payload = raw.get("payload")
    out: dict[str, Any] = {
        "schema": "easy-rev.frida.message/v1",
        "ts": time.time(),
        "type": mtype,
        "payload": payload,
    }
    if data_len is not None:
        out["data_len"] = data_len
    if mtype == "error":
        out["error"] = {
            "description": raw.get("description"),
            "stack": raw.get("stack"),
            "fileName": raw.get("fileName"),
            "lineNumber": raw.get("lineNumber"),
        }
    # Promote common send payloads
    if mtype == "send" and isinstance(payload, dict):
        out["event"] = payload.get("type") or payload.get("event") or "send"
        if "module" in payload:
            out["module"] = payload.get("module")
        if "api" in payload:
            out["api"] = payload.get("api")
    return out


@dataclass
class LiveSession:
    session_id: str
    kind: Kind
    platform: str
    target: str  # process name/pid or package
    scripts: list[str] = field(default_factory=list)
    status: str = "dry_run"
    dry_run: bool = True
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    messages: list[dict[str, Any]] = field(default_factory=list)
    log_path: str | None = None
    error: str | None = None
    hint: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    # live handles (optional)
    _frida_session: Any = field(default=None, repr=False)
    _script: Any = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _max_messages: int = 2000

    def append_message(self, msg: dict[str, Any]) -> None:
        with self._lock:
            self.messages.append(msg)
            if len(self.messages) > self._max_messages:
                self.messages = self.messages[-self._max_messages :]
            self.last_active = time.time()
            if self.log_path:
                try:
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(msg, ensure_ascii=False, default=str) + "\n")
                except Exception:  # noqa: BLE001
                    pass

    def drain(self, *, since: int = 0, limit: int = 500) -> dict[str, Any]:
        with self._lock:
            chunk = self.messages[since : since + limit]
            return {
                "session_id": self.session_id,
                "from": since,
                "to": since + len(chunk),
                "total": len(self.messages),
                "messages": chunk,
            }

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "kind": self.kind,
            "platform": self.platform,
            "target": self.target,
            "scripts": self.scripts,
            "status": self.status,
            "dry_run": self.dry_run,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "message_count": len(self.messages),
            "log_path": self.log_path,
            "error": self.error,
            "hint": self.hint,
            "meta": self.meta,
        }


_SESSIONS: dict[str, LiveSession] = {}
_SESSIONS_LOCK = threading.Lock()


def list_sessions() -> list[dict[str, Any]]:
    with _SESSIONS_LOCK:
        return [s.to_dict() for s in _SESSIONS.values()]


def get_session(session_id: str) -> LiveSession | None:
    with _SESSIONS_LOCK:
        return _SESSIONS.get(session_id)


def stop_session(session_id: str) -> dict[str, Any]:
    with _SESSIONS_LOCK:
        sess = _SESSIONS.pop(session_id, None)
    if not sess:
        return {"ok": False, "error": f"session not found: {session_id}"}
    try:
        if sess._script is not None:
            sess._script.unload()
    except Exception:  # noqa: BLE001
        pass
    try:
        if sess._frida_session is not None:
            sess._frida_session.detach()
    except Exception:  # noqa: BLE001
        pass
    sess.status = "stopped"
    return {"ok": True, "session_id": session_id, "status": "stopped"}


def _resolve_script_text(kind: Kind, scripts: list[str]) -> str:
    if kind == "desktop":
        from easy_rev.platforms.desktop.common.frida_session import DEFAULT_RECON_JS
        from easy_rev.platforms.desktop.common.frida_session import _resolve_script_text as res

        if not scripts:
            return DEFAULT_RECON_JS
        return res(scripts)
    from easy_rev.core.platform import Platform
    from easy_rev.platforms.mobile.common.frida_session import _resolve_script_text as res

    # default android recon if unspecified
    return res(Platform.ANDROID, scripts)


def start_session(
    *,
    kind: Kind,
    platform: str,
    target: str,
    scripts: list[str] | None = None,
    spawn: bool = True,
    device: str | None = None,
    host: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Start a live Frida session or dry_run stub."""
    scripts = list(scripts or [])
    sid = session_id or uuid.uuid4().hex[:12]
    out_dir = artifacts_dir() / kind / "frida" / "sessions"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"{sid}.jsonl"

    sess = LiveSession(
        session_id=sid,
        kind=kind,
        platform=platform,
        target=target,
        scripts=scripts,
        log_path=str(log_path),
    )

    # frida availability
    try:
        import frida  # noqa: F401
    except Exception as e:  # noqa: BLE001
        sess.status = "dry_run"
        sess.dry_run = True
        sess.error = f"frida not installed: {e}"
        sess.hint = "pip install 'easy-rev[frida]'"
        # synthetic hello message for schema consumers
        sess.append_message(
            normalize_frida_message(
                {"type": "send", "payload": {"type": "session", "status": "dry_run", "reason": sess.error}}
            )
        )
        with _SESSIONS_LOCK:
            _SESSIONS[sid] = sess
        return dynamic_result(
            status="dry_run",
            platform=platform,
            target=target,
            error=sess.error,
            hint=sess.hint,
            session=sess.to_dict(),
        )

    try:
        if kind == "desktop":
            from easy_rev.platforms.desktop.common.frida_session import _device, _resolve_target

            dev = _device(host)
            pid = _resolve_target(dev, target)
            frida_sess = dev.attach(pid)
            sess.meta["pid"] = pid
        else:
            from easy_rev.core.platform import Platform
            from easy_rev.platforms.mobile.common.frida_session import _get_device

            plat = Platform(platform if platform in {"android", "ios"} else "android")
            dev = _get_device(device, plat)
            if spawn:
                pid = dev.spawn([target])
                frida_sess = dev.attach(pid)
                dev.resume(pid)
                sess.meta["pid"] = pid
                sess.meta["spawn"] = True
            else:
                frida_sess = dev.attach(target)
                sess.meta["pid"] = getattr(frida_sess, "pid", None)
                sess.meta["spawn"] = False

        source = _resolve_script_text(kind, scripts)

        def on_message(message: dict, data: Any) -> None:  # noqa: ANN401
            dlen = len(data) if data is not None and hasattr(data, "__len__") else None
            sess.append_message(normalize_frida_message(message, data_len=dlen))

        script = frida_sess.create_script(source)
        script.on("message", on_message)
        script.load()
        sess._frida_session = frida_sess
        sess._script = script
        sess.status = "attached"
        sess.dry_run = False
        sess.append_message(
            normalize_frida_message(
                {"type": "send", "payload": {"type": "session", "status": "attached", "session_id": sid}}
            )
        )
    except Exception as e:  # noqa: BLE001
        sess.status = "error"
        sess.dry_run = False
        sess.error = str(e)
        sess.hint = "check process/package, frida-server, USB, permissions"
        with _SESSIONS_LOCK:
            _SESSIONS[sid] = sess
        return dynamic_result(
            status="error",
            platform=platform,
            target=target,
            error=sess.error,
            hint=sess.hint,
            session=sess.to_dict(),
        )

    with _SESSIONS_LOCK:
        _SESSIONS[sid] = sess
    return dynamic_result(
        status="attached",
        platform=platform,
        target=target,
        session=sess.to_dict(),
    )


def eval_js(session_id: str, source: str) -> dict[str, Any]:
    """Load additional JS into an attached session (or record dry_run eval)."""
    sess = get_session(session_id)
    if not sess:
        return {"ok": False, "error": f"session not found: {session_id}"}
    sess.last_active = time.time()
    if sess.dry_run or sess._frida_session is None:
        msg = normalize_frida_message(
            {"type": "send", "payload": {"type": "eval_dry_run", "source_len": len(source)}}
        )
        sess.append_message(msg)
        return {
            "ok": True,
            "status": "dry_run",
            "session_id": session_id,
            "message": msg,
        }
    try:

        def on_message(message: dict, data: Any) -> None:  # noqa: ANN401
            dlen = len(data) if data is not None and hasattr(data, "__len__") else None
            sess.append_message(normalize_frida_message(message, data_len=dlen))

        script = sess._frida_session.create_script(source)
        script.on("message", on_message)
        script.load()
        # keep last script ref
        sess._script = script
        return {"ok": True, "status": "attached", "session_id": session_id}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "status": "error", "error": str(e), "session_id": session_id}


def drain_messages(session_id: str, *, since: int = 0, limit: int = 500) -> dict[str, Any]:
    sess = get_session(session_id)
    if not sess:
        return {"ok": False, "error": f"session not found: {session_id}"}
    out = sess.drain(since=since, limit=limit)
    out["ok"] = True
    out["status"] = sess.status
    return out


def session_summary(session_id: str) -> dict[str, Any]:
    sess = get_session(session_id)
    if not sess:
        return {"ok": False, "error": f"session not found: {session_id}"}
    # categorize events
    events: dict[str, int] = {}
    for m in sess.messages:
        ev = str(m.get("event") or m.get("type") or "unknown")
        events[ev] = events.get(ev, 0) + 1
    return {
        "ok": True,
        "session": sess.to_dict(),
        "event_counts": events,
        "updated_at": datetime.now(UTC).isoformat(),
    }
