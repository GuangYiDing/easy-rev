"""Unified result status for dynamic RE paths (Frida / browser).

Semantics:
- status=attached  → really instrumented / browser live
- status=dry_run   → dependency missing; contract succeeded, no attach
- status=error     → attempted but failed (process/device/permission)
- ok               → call completed without unexpected crash (True for dry_run too)
- degraded         → ran a fallback path (e.g. offline web chain)
"""

from __future__ import annotations

from typing import Any, Literal

Status = Literal["attached", "dry_run", "error", "static", "offline", "degraded"]


def dynamic_result(
    *,
    status: Status,
    platform: str,
    target: str | None = None,
    error: str | None = None,
    hint: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a normalized dynamic-path result dict."""
    attached = status == "attached"
    dry_run = status == "dry_run"
    # dry_run is an intentional successful contract; error is failure
    ok = status in {"attached", "dry_run", "static", "offline", "degraded"}
    out: dict[str, Any] = {
        "ok": ok,
        "status": status,
        "attached": attached,
        "dry_run": dry_run,
        "degraded": status in {"dry_run", "offline", "degraded"},
        "platform": platform,
    }
    if target is not None:
        out["target"] = target
    if error:
        out["error"] = error
    if hint:
        out["hint"] = hint
    out.update(extra)
    return out


def install_hints(missing: list[str]) -> list[str]:
    """Human-installable commands for common optional deps."""
    table = {
        "frida": "pip install 'easy-rev[frida]'",
        "camoufox": "pip install 'easy-rev[web]' && python -m camoufox fetch",
        "curl_cffi": "pip install 'easy-rev[tls]'",
        "androguard": "pip install 'easy-rev[android]'",
        "playwright": "pip install playwright && playwright install chromium",
        "adb": "install Android platform-tools (adb on PATH)",
        "idevice": "brew install libimobiledevice  # or equivalent",
    }
    return [table.get(m, f"install {m}") for m in missing]
