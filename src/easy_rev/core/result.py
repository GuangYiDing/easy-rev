"""Unified result status for dynamic RE paths (Frida / browser).

Semantics:
- status=attached  → really instrumented / browser live
- status=dry_run   → dependency missing; contract succeeded, no attach
- status=error     → attempted but failed (process/device/permission)
- status=static    → static-only analysis path
- status=offline   → offline protocol chain (no browser)
- status=degraded  → fell back from preferred path
- ok               → call completed without unexpected crash (True for dry_run too)
- degraded         → ran a fallback path (e.g. offline web chain)
- confidence       → high | medium | low | none (agent-facing trust)
"""

from __future__ import annotations

from typing import Any, Literal

Status = Literal["attached", "dry_run", "error", "static", "offline", "degraded"]
Confidence = Literal["high", "medium", "low", "none"]

STATUS_OK: set[str] = {"attached", "dry_run", "static", "offline", "degraded"}
STATUS_DEGRADED: set[str] = {"dry_run", "offline", "degraded"}


def dynamic_result(
    *,
    status: Status,
    platform: str,
    target: str | None = None,
    error: str | None = None,
    hint: str | None = None,
    confidence: Confidence | None = None,
    next_steps: list[str] | None = None,
    blocking_issues: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a normalized dynamic-path result dict."""
    attached = status == "attached"
    dry_run = status == "dry_run"
    # dry_run is an intentional successful contract; error is failure
    ok = status in STATUS_OK
    if confidence is None:
        confidence = _default_confidence(status, error=error, extra=extra)
    out: dict[str, Any] = {
        "ok": ok,
        "status": status,
        "attached": attached,
        "dry_run": dry_run,
        "degraded": status in STATUS_DEGRADED,
        "platform": platform,
        "confidence": confidence,
    }
    if target is not None:
        out["target"] = target
    if error:
        out["error"] = error
    if hint:
        out["hint"] = hint
    if next_steps:
        out["next_steps"] = list(next_steps)
    if blocking_issues:
        out["blocking_issues"] = list(blocking_issues)
    out.update(extra)
    return out


def _default_confidence(
    status: Status,
    *,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> Confidence:
    extra = extra or {}
    if status == "error" or error:
        return "none"
    if status == "attached":
        return "high"
    if status == "static":
        # static-only is useful but incomplete for protocol/frida claims
        return "medium" if extra.get("findings") or extra.get("artifacts") else "low"
    if status in {"offline", "degraded", "dry_run"}:
        return "low"
    return "low"


def derive_status(
    *,
    has_static: bool = False,
    dyn: dict[str, Any] | None = None,
    preferred: Status | None = None,
) -> Status:
    """Derive a unified status from static/dynamic explore parts."""
    if preferred is not None:
        return preferred
    dyn = dyn or {}
    if dyn.get("attached") or dyn.get("status") == "attached":
        return "attached"
    dyn_status = dyn.get("status")
    if dyn_status in {"dry_run", "error", "degraded", "offline", "static"}:
        return dyn_status  # type: ignore[return-value]
    if dyn.get("dry_run"):
        return "dry_run"
    if dyn.get("error") and not has_static:
        return "error"
    if has_static:
        return "static"
    if dyn:
        return "error"
    return "error"


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


def merge_envelope(base: dict[str, Any], *overlays: dict[str, Any] | None) -> dict[str, Any]:
    """Shallow-merge overlay dicts onto a result envelope (later wins for scalars)."""
    out = dict(base)
    for ov in overlays:
        if not ov:
            continue
        for k, v in ov.items():
            if v is None:
                continue
            if k in {"next_steps", "blocking_issues", "artifacts"} and isinstance(v, list):
                prev = list(out.get(k) or [])
                for item in v:
                    if item not in prev:
                        prev.append(item)
                out[k] = prev
            else:
                out[k] = v
    return out
