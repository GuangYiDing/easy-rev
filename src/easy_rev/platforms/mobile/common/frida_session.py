"""Frida spawn/attach helpers for Android / iOS (commercial dry-run contract)."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from easy_rev.core.paths import artifacts_dir
from easy_rev.core.platform import Platform

DEFAULT_ANDROID_JS = r"""
'use strict';
const report = { runtime: 'android', classes_sample: [] };
if (Java.available) {
  Java.perform(function () {
    const groups = [];
    Java.enumerateLoadedClasses({
      onMatch: function (name) {
        if (/crypto|ssl|okhttp|retrofit|sign|token|http|CertificatePinner|TrustManager/i.test(name)) {
          groups.push(name);
        }
      },
      onComplete: function () {}
    });
    report.classes_sample = groups.slice(0, 100);
    send({ type: 'recon', payload: report });
  });
} else {
  send({ type: 'recon', payload: { runtime: 'android', error: 'Java.unavailable' } });
}
"""

DEFAULT_IOS_JS = r"""
'use strict';
const report = { runtime: 'ios', modules: [], exports_sample: [] };
const mods = Process.enumerateModules().slice(0, 80);
report.modules = mods.map(m => ({ name: m.name, base: m.base.toString(), path: m.path }));
for (const m of mods.slice(0, 15)) {
  try {
    const exps = m.enumerateExports().filter(e =>
      /ssl|tls|crypt|sign|hash|SecItem|CCCrypt|NSURL/i.test(e.name)
    ).slice(0, 40);
    if (exps.length) {
      report.exports_sample.push({ module: m.name, exports: exps.map(e => e.name) });
    }
  } catch (e) {}
}
send({ type: 'recon', payload: report });
"""


def frida_available() -> tuple[bool, str | None]:
    try:
        import frida  # noqa: F401

        return True, getattr(__import__("frida"), "__version__", "unknown")
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def dry_run_result(
    package: str,
    *,
    platform: Platform,
    reason: str,
    hint: str,
) -> dict[str, Any]:
    from easy_rev.core.result import dynamic_result

    return dynamic_result(
        status="dry_run",
        platform=platform.value,
        target=package,
        error=reason,
        hint=hint,
        package=package,
        message_count=0,
        recon=None,
        log_path=None,
    )


def _get_device(device_id: str | None = None, platform: Platform = Platform.ANDROID):
    import frida

    dm = frida.get_device_manager()
    if device_id:
        if ":" in device_id and device_id.count(":") <= 2:
            try:
                return dm.add_remote_device(device_id)
            except Exception:  # noqa: BLE001
                pass
        for d in dm.enumerate_devices():
            if d.id == device_id or device_id in (d.name or ""):
                return d
        return dm.add_remote_device(device_id)

    for d in dm.enumerate_devices():
        if d.type == "usb":
            return d
    return frida.get_usb_device(timeout=3)


def _resolve_script_text(platform: Platform, scripts: list[str]) -> str:
    from easy_rev.platforms.mobile.scripts import list_scripts, load_script

    base = DEFAULT_ANDROID_JS if platform is Platform.ANDROID else DEFAULT_IOS_JS
    parts = [base]
    for s in scripts:
        s = str(s).strip()
        if not s:
            continue
        p = Path(s)
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
            continue
        try:
            parts.append(load_script(s if s.endswith(".js") else f"{s}.js"))
            continue
        except FileNotFoundError:
            pass
        if s in list_scripts() or f"{s}.js" in list_scripts():
            parts.append(load_script(s if s.endswith(".js") else f"{s}.js"))
            continue
        parts.append(s)
    return "\n;\n".join(parts)


async def explore_app(
    package: str,
    *,
    platform: Platform = Platform.ANDROID,
    device: str | None = None,
    scripts: list[str] | None = None,
    spawn: bool = True,
    duration_s: float = 5.0,
) -> dict[str, Any]:
    return await capture_app(
        package,
        platform=platform,
        device=device,
        scripts=scripts or [],
        spawn=spawn,
        duration_s=duration_s,
    )


async def capture_app(
    package: str,
    *,
    platform: Platform = Platform.ANDROID,
    device: str | None = None,
    scripts: list[str] | None = None,
    spawn: bool = True,
    duration_s: float = 10.0,
) -> dict[str, Any]:
    ok, ver_or_err = frida_available()
    if not ok:
        return dry_run_result(
            package,
            platform=platform,
            reason=f"frida not installed: {ver_or_err}",
            hint="pip install 'easy-rev[frida]'; start frida-server on device",
        )

    messages: list[dict[str, Any]] = []
    out_dir = artifacts_dir() / "mobile" / "frida"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    log_path = out_dir / f"capture-{ts}.jsonl"

    def on_message(message: dict, data: Any) -> None:  # noqa: ANN401
        rec = {"ts": time.time(), "message": message}
        messages.append(rec)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")

    try:
        dev = _get_device(device, platform)
    except Exception as e:  # noqa: BLE001
        from easy_rev.core.result import dynamic_result

        return dynamic_result(
            status="error",
            platform=platform.value,
            target=package,
            error=f"device not found: {e}",
            hint="connect USB device with frida-server, or pass device=",
            package=package,
            frida_version=ver_or_err,
        )

    session = None
    pid = None
    try:
        if spawn:
            pid = dev.spawn([package])
            session = dev.attach(pid)
        else:
            session = dev.attach(package)
            pid = getattr(session, "pid", None)

        source = _resolve_script_text(platform, scripts or [])
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        if spawn and pid is not None:
            dev.resume(pid)
        time.sleep(max(0.5, float(duration_s)))
    except Exception as e:  # noqa: BLE001
        from easy_rev.core.result import dynamic_result

        return dynamic_result(
            status="error",
            platform=platform.value,
            target=package,
            error=str(e),
            hint="check package id, frida-server arch, and USB authorization",
            package=package,
            device=getattr(dev, "id", None),
            log_path=str(log_path) if log_path.exists() else None,
        )
    finally:
        try:
            if session is not None:
                session.detach()
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
        target=package,
        pid=pid,
        package=package,
        device=getattr(dev, "id", None),
        frida_version=ver_or_err,
        message_count=len(messages),
        recon=recon,
        log_path=str(log_path),
        duration_s=duration_s,
        spawn=spawn,
        scripts=scripts or [],
    )
    summary_path = out_dir / f"summary-{ts}.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    summary["summary_path"] = str(summary_path)
    return summary


def list_apps(device: str | None = None) -> list[dict[str, Any]]:
    ok, err = frida_available()
    if not ok:
        return [{"error": err, "dry_run": True, "hint": "pip install 'easy-rev[frida]'"}]
    try:
        dev = _get_device(device)
        apps = dev.enumerate_applications()
        return [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps]
    except Exception as e:  # noqa: BLE001
        return [{"error": str(e), "hint": "no USB device / frida-server"}]
