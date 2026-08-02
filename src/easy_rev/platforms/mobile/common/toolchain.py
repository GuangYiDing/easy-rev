"""Detect mobile RE toolchains (adb, frida, idevice, etc.)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any

from easy_rev.core.platform import Platform


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], timeout: float = 8.0) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip() or None
    except Exception:  # noqa: BLE001
        return None


def probe_mobile_toolchain(platform: Platform) -> dict[str, Any]:
    info: dict[str, Any] = {
        "python": sys.version.split()[0],
        "host_os": sys.platform,
        "frida": False,
        "frida_version": None,
        "tools": {},
        "devices": [],
    }
    try:
        import frida

        info["frida"] = True
        info["frida_version"] = getattr(frida, "__version__", "unknown")
    except Exception as e:  # noqa: BLE001
        info["frida_error"] = str(e)

    tools = ["adb", "fastboot", "aapt", "aapt2", "apktool", "jadx", "zipalign"]
    if platform is Platform.IOS or True:
        tools += [
            "idevice_id",
            "ideviceinfo",
            "ideviceinstaller",
            "frida",
            "objection",
        ]
    for t in tools:
        path = _which(t)
        info["tools"][t] = {"available": bool(path), "path": path}

    # ADB devices
    if info["tools"].get("adb", {}).get("available"):
        out = _run(["adb", "devices", "-l"])
        devices = []
        if out:
            for line in out.splitlines()[1:]:
                line = line.strip()
                if not line or "offline" in line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    devices.append({"serial": parts[0], "raw": line, "os": "android"})
        info["devices"] = devices

    # iOS via libimobiledevice
    if info["tools"].get("idevice_id", {}).get("available"):
        out = _run(["idevice_id", "-l"])
        if out:
            for udid in out.splitlines():
                udid = udid.strip()
                if udid:
                    info["devices"].append({"udid": udid, "os": "ios"})

    # Frida USB devices
    if info["frida"]:
        try:
            import frida

            dm = frida.get_device_manager()
            for d in dm.enumerate_devices():
                info.setdefault("frida_devices", []).append(
                    {"id": d.id, "name": d.name, "type": d.type}
                )
        except Exception as e:  # noqa: BLE001
            info["frida_devices_error"] = str(e)

    # Optional androguard
    try:
        import androguard  # noqa: F401

        info["androguard"] = True
    except Exception:  # noqa: BLE001
        info["androguard"] = False

    from easy_rev.core.deps import preflight

    key = "android" if platform is Platform.ANDROID else "ios"
    pf = preflight(key)
    block = (pf.get("platforms") or {}).get(key) or {}
    info["ready"] = block.get("ready")
    info["score"] = block.get("score")
    info["missing"] = block.get("missing")
    info["install_hints"] = pf.get("install_hints") or []
    info["capabilities"] = {
        "static_apk": platform is Platform.ANDROID,
        "static_ipa": platform is Platform.IOS or True,
        "dynamic": bool(info["frida"]),
        "adb": bool(info["tools"].get("adb", {}).get("available")),
        "device_count": len(info.get("devices") or []),
        "frida_device_count": len(info.get("frida_devices") or []),
        "androguard": bool(info.get("androguard")),
    }
    info["next_steps"] = pf.get("next_steps") or []
    return info
