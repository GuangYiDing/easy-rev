"""Frida attach / spawn helpers for desktop processes (commercial dry-run contract)."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from easy_rev.core.paths import artifacts_dir
from easy_rev.core.platform import Platform

DEFAULT_RECON_JS = r"""
'use strict';
const report = { modules: [], exports_sample: [], platform: Process.platform, arch: Process.arch };

function safe(fn, fallback) {
  try { return fn(); } catch (e) { return fallback; }
}

const mods = safe(() => Process.enumerateModules(), []);
report.modules = mods.slice(0, 100).map(m => ({
  name: m.name, base: m.base.toString(), size: m.size, path: m.path
}));

for (const m of mods.slice(0, 20)) {
  const exps = safe(() => m.enumerateExports(), []);
  const interesting = exps.filter(e =>
    /crypt|ssl|tls|sign|hash|aes|rsa|http|socket|send|recv|bcrypt|CCCrypt/i.test(e.name)
  ).slice(0, 50);
  if (interesting.length) {
    report.exports_sample.push({
      module: m.name,
      exports: interesting.map(e => ({ name: e.name, type: e.type, address: e.address.toString() }))
    });
  }
}

send({ type: 'recon', payload: report });
"""


def frida_available() -> tuple[bool, str | None]:
    try:
        import frida  # noqa: F401

        return True, getattr(__import__("frida"), "__version__", "unknown")
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def _device(host: str | None = None):
    import frida

    if host:
        return frida.get_device_manager().add_remote_device(host)
    return frida.get_local_device()


def _resolve_target(device, process: str):
    process = str(process).strip()
    if process.isdigit():
        return int(process)
    try:
        return device.get_process(process).pid
    except Exception:  # noqa: BLE001
        pass
    procs = device.enumerate_processes()
    needle = process.lower()
    for p in procs:
        if needle in p.name.lower():
            return p.pid
    raise RuntimeError(f"process not found: {process}")


def _resolve_script_text(scripts: list[str]) -> str:
    """Load script paths (bundled or filesystem) or inline JS."""
    from easy_rev.platforms.desktop.scripts import list_scripts, load_script

    parts = [DEFAULT_RECON_JS]
    for s in scripts:
        s = str(s).strip()
        if not s:
            continue
        p = Path(s)
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
            continue
        # bundled short name
        try:
            parts.append(load_script(s))
            continue
        except FileNotFoundError:
            pass
        # bare name in list
        if s in list_scripts() or f"{s}.js" in list_scripts():
            parts.append(load_script(s if s.endswith(".js") else f"{s}.js"))
            continue
        parts.append(s)  # inline
    return "\n;\n".join(parts)


def dry_run_result(
    process: str,
    *,
    platform: Platform,
    reason: str,
    hint: str,
) -> dict[str, Any]:
    from easy_rev.core.result import dynamic_result

    return dynamic_result(
        status="dry_run",
        platform=platform.value,
        target=process,
        error=reason,
        hint=hint,
        process=process,
        message_count=0,
        recon=None,
        log_path=None,
    )


async def explore_process(
    process: str,
    *,
    platform: Platform = Platform.MACOS,
    scripts: list[str] | None = None,
    duration_s: float = 5.0,
    host: str | None = None,
) -> dict[str, Any]:
    return await capture_process(
        process,
        platform=platform,
        scripts=scripts or [],
        duration_s=duration_s,
        host=host,
    )


async def capture_process(
    process: str,
    *,
    platform: Platform = Platform.MACOS,
    scripts: list[str] | None = None,
    duration_s: float = 10.0,
    host: str | None = None,
) -> dict[str, Any]:
    ok, ver_or_err = frida_available()
    if not ok:
        return dry_run_result(
            process,
            platform=platform,
            reason=f"frida not installed: {ver_or_err}",
            hint="pip install 'easy-rev[frida]'",
        )

    messages: list[dict[str, Any]] = []
    out_dir = artifacts_dir() / "desktop" / "frida"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    log_path = out_dir / f"capture-{ts}.jsonl"

    def on_message(message: dict, data: Any) -> None:  # noqa: ANN401
        rec = {"ts": time.time(), "message": message}
        if data is not None:
            rec["data_len"] = len(data) if hasattr(data, "__len__") else None
        messages.append(rec)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")

    try:
        device = _device(host)
        pid = _resolve_target(device, process)
    except Exception as e:  # noqa: BLE001
        from easy_rev.core.result import dynamic_result

        return dynamic_result(
            status="error",
            platform=platform.value,
            target=process,
            error=str(e),
            hint="check process name/pid; use desktop.ps",
            process=process,
            frida_version=ver_or_err,
        )

    try:
        session = device.attach(pid)
        source = _resolve_script_text(scripts or [])
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        time.sleep(max(0.5, float(duration_s)))
    except Exception as e:  # noqa: BLE001
        from easy_rev.core.result import dynamic_result

        return dynamic_result(
            status="error",
            platform=platform.value,
            target=process,
            error=str(e),
            hint="permission/SIP/code-signing may block attach",
            process=process,
            pid=pid,
            log_path=str(log_path) if log_path.exists() else None,
        )
    finally:
        try:
            script.unload()  # type: ignore[name-defined]
        except Exception:  # noqa: BLE001
            pass
        try:
            session.detach()  # type: ignore[name-defined]
        except Exception:  # noqa: BLE001
            pass

    recon = None
    for m in messages:
        msg = m.get("message") or {}
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "recon":
                recon = payload.get("payload")

    from easy_rev.core.result import dynamic_result

    summary = dynamic_result(
        status="attached",
        platform=platform.value,
        target=process,
        pid=pid,
        process=process,
        frida_version=ver_or_err,
        message_count=len(messages),
        recon=recon,
        log_path=str(log_path),
        duration_s=duration_s,
        scripts=scripts or [],
    )
    summary_path = out_dir / f"summary-{ts}.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    summary["summary_path"] = str(summary_path)
    return summary


def list_processes(host: str | None = None) -> list[dict[str, Any]]:
    ok, err = frida_available()
    if not ok:
        return [{"error": err, "dry_run": True, "hint": "pip install 'easy-rev[frida]'"}]
    device = _device(host)
    return [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]
