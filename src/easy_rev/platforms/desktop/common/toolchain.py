"""Detect desktop RE toolchains (Frida, dumpbin, otool, lldb, etc.)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any

from easy_rev.core.platform import Platform


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run_version(cmd: list[str]) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = (r.stdout or r.stderr or "").strip().splitlines()
        return out[0] if out else None
    except Exception:  # noqa: BLE001
        return None


def probe_desktop_toolchain(platform: Platform) -> dict[str, Any]:
    from easy_rev.core.deps import preflight

    info: dict[str, Any] = {
        "python": sys.version.split()[0],
        "host_os": sys.platform,
        "frida": False,
        "frida_version": None,
        "tools": {},
    }
    try:
        import frida

        info["frida"] = True
        info["frida_version"] = getattr(frida, "__version__", "unknown")
    except Exception as e:  # noqa: BLE001
        info["frida_error"] = str(e)

    common = ["lldb", "gdb", "objdump", "nm", "strings", "file", "hexdump"]
    if platform is Platform.MACOS or sys.platform == "darwin":
        common += ["otool", "codesign", "dwarfdump", "vmmap", "sample"]
    if platform is Platform.WINDOWS or sys.platform.startswith("win"):
        common += ["dumpbin", "sigcheck", "pdbcopy"]

    for t in common:
        path = _which(t)
        info["tools"][t] = {"available": bool(path), "path": path}

    if info["tools"].get("otool", {}).get("available"):
        info["tools"]["otool"]["version"] = _run_version(["otool", "--version"])

    key = "macos" if platform is Platform.MACOS else "windows"
    pf = preflight(key)
    block = (pf.get("platforms") or {}).get(key) or {}
    info["ready"] = block.get("ready")
    info["score"] = block.get("score")
    info["missing"] = block.get("missing")
    info["install_hints"] = pf.get("install_hints") or []
    info["capabilities"] = {
        "static": True,  # pure Python PE/Mach-O always available
        "dynamic": bool(info["frida"]),
        "otool": bool(info["tools"].get("otool", {}).get("available")),
        "codesign": bool(info["tools"].get("codesign", {}).get("available")),
    }
    info["next_steps"] = pf.get("next_steps") or []
    return info
