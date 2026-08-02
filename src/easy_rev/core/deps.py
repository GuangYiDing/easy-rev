"""Dependency catalog, preflight checks, and safe auto-fix for RE toolchains.

Design:
- Catalog is the single source of truth for doctor / preflight / fix.
- Auto-fix only runs *safe* installers (pip extras, camoufox fetch, playwright browsers).
- System package managers (brew/apt) are proposed as commands; only run when
  explicitly allowed via allow_system=True.
"""

from __future__ import annotations

import platform as py_platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Level = Literal["required", "recommended", "optional"]
Kind = Literal["pip", "cli", "python_module", "post_cmd"]
Host = Literal["any", "darwin", "linux", "win32"]


@dataclass
class DepSpec:
    id: str
    title: str
    kind: Kind
    level: Level
    platforms: list[str]  # web|windows|macos|android|ios|all
    paths: list[str]  # capability tags: static|dynamic|browser|tls|bridge|session|...
    # detection
    module: str | None = None  # import name
    cli: str | None = None  # PATH binary
    # fix
    pip_extra: str | None = None  # easy-rev[extra]
    pip_packages: list[str] = field(default_factory=list)
    post_cmds: list[list[str]] = field(default_factory=list)  # after pip
    brew: str | None = None
    apt: str | None = None
    host: Host = "any"
    note: str = ""
    auto_fixable: bool = False  # pip/post only by default


# --- Catalog -----------------------------------------------------------------

DEP_CATALOG: list[DepSpec] = [
    # Python core always present when easy-rev runs
    DepSpec(
        id="python",
        title="Python runtime",
        kind="cli",
        level="required",
        platforms=["all"],
        paths=["core"],
        cli="python3",
        note="easy-rev requires Python >=3.11",
        auto_fixable=False,
    ),
    # Web
    DepSpec(
        id="camoufox",
        title="Camoufox anti-detect browser",
        kind="python_module",
        level="recommended",
        platforms=["web"],
        paths=["browser", "explore", "capture", "session"],
        module="camoufox",
        pip_extra="web",
        pip_packages=["camoufox[geoip]"],
        post_cmds=[[sys.executable, "-m", "camoufox", "fetch"]],
        note="Primary clean-browser RE engine",
        auto_fixable=True,
    ),
    DepSpec(
        id="playwright",
        title="Playwright (optional browser backend)",
        kind="python_module",
        level="optional",
        platforms=["web"],
        paths=["browser", "capture"],
        module="playwright",
        pip_packages=["playwright"],
        post_cmds=[[sys.executable, "-m", "playwright", "install", "chromium"]],
        note="Fallback when Camoufox unavailable",
        auto_fixable=True,
    ),
    DepSpec(
        id="curl_cffi",
        title="curl_cffi TLS fingerprint client",
        kind="python_module",
        level="recommended",
        platforms=["web"],
        paths=["tls", "protocol", "http"],
        module="curl_cffi",
        pip_extra="tls",
        pip_packages=["curl_cffi"],
        note="Protocol replay with browser TLS fingerprint",
        auto_fixable=True,
    ),
    DepSpec(
        id="httpx",
        title="httpx HTTP client",
        kind="python_module",
        level="required",
        platforms=["web", "all"],
        paths=["http", "core"],
        module="httpx",
        pip_packages=["httpx"],
        auto_fixable=True,
    ),
    # Dynamic (all native platforms)
    DepSpec(
        id="frida",
        title="Frida dynamic instrumentation",
        kind="python_module",
        level="recommended",
        platforms=["windows", "macos", "android", "ios"],
        paths=["dynamic", "frida", "session"],
        module="frida",
        pip_extra="frida",
        pip_packages=["frida", "frida-tools"],
        note="Also need frida-server on mobile devices",
        auto_fixable=True,
    ),
    DepSpec(
        id="frida_cli",
        title="frida CLI (frida-tools)",
        kind="cli",
        level="optional",
        platforms=["windows", "macos", "android", "ios"],
        paths=["dynamic", "frida"],
        cli="frida",
        pip_extra="frida",
        pip_packages=["frida-tools"],
        auto_fixable=True,
    ),
    # Android
    DepSpec(
        id="androguard",
        title="androguard deep APK analysis",
        kind="python_module",
        level="optional",
        platforms=["android"],
        paths=["static", "apk"],
        module="androguard",
        pip_extra="android",
        pip_packages=["androguard"],
        auto_fixable=True,
    ),
    DepSpec(
        id="adb",
        title="Android Debug Bridge",
        kind="cli",
        level="recommended",
        platforms=["android"],
        paths=["dynamic", "device", "frida"],
        cli="adb",
        brew="android-platform-tools",
        note="USB debugging / frida-server push",
        auto_fixable=False,
    ),
    DepSpec(
        id="aapt",
        title="Android aapt",
        kind="cli",
        level="optional",
        platforms=["android"],
        paths=["static", "apk"],
        cli="aapt",
        note="From Android build-tools",
        auto_fixable=False,
    ),
    DepSpec(
        id="jadx",
        title="jadx decompiler",
        kind="cli",
        level="optional",
        platforms=["android"],
        paths=["static", "apk", "decompile"],
        cli="jadx",
        brew="jadx",
        auto_fixable=False,
    ),
    DepSpec(
        id="apktool",
        title="apktool",
        kind="cli",
        level="optional",
        platforms=["android"],
        paths=["static", "apk", "decompile"],
        cli="apktool",
        brew="apktool",
        auto_fixable=False,
    ),
    # iOS
    DepSpec(
        id="idevice_id",
        title="libimobiledevice (idevice_id)",
        kind="cli",
        level="recommended",
        platforms=["ios"],
        paths=["device", "dynamic"],
        cli="idevice_id",
        brew="libimobiledevice",
        host="darwin",
        auto_fixable=False,
    ),
    DepSpec(
        id="ideviceinfo",
        title="ideviceinfo",
        kind="cli",
        level="optional",
        platforms=["ios"],
        paths=["device"],
        cli="ideviceinfo",
        brew="libimobiledevice",
        host="darwin",
        auto_fixable=False,
    ),
    # Desktop macOS
    DepSpec(
        id="otool",
        title="otool (Xcode CLT)",
        kind="cli",
        level="recommended",
        platforms=["macos"],
        paths=["static", "macho"],
        cli="otool",
        host="darwin",
        note="xcode-select --install",
        auto_fixable=False,
    ),
    DepSpec(
        id="codesign",
        title="codesign",
        kind="cli",
        level="recommended",
        platforms=["macos"],
        paths=["static", "macho", "signing"],
        cli="codesign",
        host="darwin",
        auto_fixable=False,
    ),
    DepSpec(
        id="lldb",
        title="lldb debugger",
        kind="cli",
        level="optional",
        platforms=["macos", "windows"],
        paths=["dynamic", "debug"],
        cli="lldb",
        auto_fixable=False,
    ),
    DepSpec(
        id="nm",
        title="nm symbol table tool",
        kind="cli",
        level="optional",
        platforms=["macos", "windows"],
        paths=["static"],
        cli="nm",
        auto_fixable=False,
    ),
    DepSpec(
        id="objdump",
        title="objdump",
        kind="cli",
        level="optional",
        platforms=["macos", "windows"],
        paths=["static"],
        cli="objdump",
        auto_fixable=False,
    ),
    DepSpec(
        id="file",
        title="file(1) magic identification",
        kind="cli",
        level="optional",
        platforms=["macos", "windows", "android", "ios"],
        paths=["static"],
        cli="file",
        auto_fixable=False,
    ),
    # MCP
    DepSpec(
        id="mcp",
        title="MCP Python SDK",
        kind="python_module",
        level="optional",
        platforms=["all"],
        paths=["mcp", "ai"],
        module="mcp",
        pip_extra="mcp",
        pip_packages=["mcp"],
        auto_fixable=True,
    ),
]


def _host_ok(spec: DepSpec) -> bool:
    if spec.host == "any":
        return True
    sysname = sys.platform
    if spec.host == "darwin":
        return sysname == "darwin"
    if spec.host == "linux":
        return sysname.startswith("linux")
    if spec.host == "win32":
        return sysname.startswith("win")
    return True


def _platform_match(spec: DepSpec, platform: str | None) -> bool:
    if platform in (None, "all"):
        return True
    if "all" in spec.platforms:
        return True
    return platform in spec.platforms


def detect_dep(spec: DepSpec) -> dict[str, Any]:
    """Detect one dependency; returns structured status."""
    present = False
    detail: dict[str, Any] = {"id": spec.id, "title": spec.title, "kind": spec.kind, "level": spec.level}
    if not _host_ok(spec):
        detail.update({"present": False, "skipped": True, "reason": f"host {sys.platform} != {spec.host}"})
        return detail

    if spec.kind in {"python_module", "pip"} or spec.module:
        mod = spec.module or spec.id
        try:
            m = __import__(mod)
            present = True
            detail["version"] = getattr(m, "__version__", None)
            detail["module"] = mod
        except Exception as e:  # noqa: BLE001
            detail["error"] = str(e)
            detail["module"] = mod

    if spec.cli:
        path = shutil.which(spec.cli)
        detail["cli"] = spec.cli
        detail["path"] = path
        if path:
            present = True
            # light version probe
            for args in ([spec.cli, "--version"], [spec.cli, "-v"], [spec.cli, "version"]):
                try:
                    r = subprocess.run(args, capture_output=True, text=True, timeout=4)
                    line = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
                    if line:
                        detail["version_line"] = line[0][:200]
                        break
                except Exception:  # noqa: BLE001
                    continue

    if spec.id == "python":
        present = True
        detail["version"] = sys.version.split()[0]
        detail["executable"] = sys.executable

    detail["present"] = present
    detail["auto_fixable"] = bool(spec.auto_fixable and (spec.pip_packages or spec.pip_extra or spec.post_cmds))
    detail["install"] = install_commands(spec)
    detail["paths"] = list(spec.paths)
    detail["platforms"] = list(spec.platforms)
    if spec.note:
        detail["note"] = spec.note
    return detail


def install_commands(spec: DepSpec) -> list[str]:
    cmds: list[str] = []
    if spec.pip_extra:
        cmds.append(f"{sys.executable} -m pip install 'easy-rev[{spec.pip_extra}]'")
    elif spec.pip_packages:
        pkgs = " ".join(spec.pip_packages)
        cmds.append(f"{sys.executable} -m pip install {pkgs}")
    for c in spec.post_cmds:
        cmds.append(" ".join(c))
    if spec.brew and sys.platform == "darwin":
        cmds.append(f"brew install {spec.brew}")
    if spec.apt and sys.platform.startswith("linux"):
        cmds.append(f"sudo apt-get install -y {spec.apt}")
    if not cmds and spec.cli:
        cmds.append(f"install '{spec.cli}' and ensure it is on PATH")
    return cmds


def catalog_for(platform: str | None = None, *, path: str | None = None) -> list[DepSpec]:
    out: list[DepSpec] = []
    for spec in DEP_CATALOG:
        if not _host_ok(spec):
            continue
        if not _platform_match(spec, platform):
            continue
        if path and path not in spec.paths and "all" not in spec.paths:
            # path filter: allow core always
            if "core" not in spec.paths:
                continue
        out.append(spec)
    return out


def preflight(
    platform: str | None = "all",
    *,
    path: str | None = None,
    include_optional: bool = True,
) -> dict[str, Any]:
    """Run dependency preflight for a platform (or all)."""
    plat = (platform or "all").lower()
    platforms = (
        ["web", "windows", "macos", "android", "ios"]
        if plat == "all"
        else [plat]
    )
    by_platform: dict[str, Any] = {}
    missing_required: list[str] = []
    missing_recommended: list[str] = []
    missing_optional: list[str] = []
    fixable: list[str] = []
    all_checks: list[dict[str, Any]] = []

    for p in platforms:
        checks = []
        for spec in catalog_for(p, path=path):
            if not include_optional and spec.level == "optional":
                continue
            det = detect_dep(spec)
            det["platform"] = p
            checks.append(det)
            all_checks.append(det)
            if det.get("skipped"):
                continue
            if det.get("present"):
                continue
            if spec.level == "required":
                missing_required.append(spec.id)
            elif spec.level == "recommended":
                missing_recommended.append(spec.id)
            else:
                missing_optional.append(spec.id)
            if det.get("auto_fixable"):
                fixable.append(spec.id)
        # readiness score (required + recommended)
        relevant = [c for c in checks if not c.get("skipped")]
        rec = [c for c in relevant if c.get("level") in {"required", "recommended"}]
        rec_ok = sum(1 for c in rec if c.get("present"))
        score = int(100 * rec_ok / len(rec)) if rec else 100
        ready = all(c.get("present") for c in relevant if c.get("level") == "required")
        ready = ready and score >= 50
        by_platform[p] = {
            "checks": checks,
            "score": score,
            "ready": ready,
            "missing": [c["id"] for c in relevant if not c.get("present")],
            "present": [c["id"] for c in relevant if c.get("present")],
        }

    # de-dupe id lists
    def uniq(xs: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    missing_required = uniq(missing_required)
    missing_recommended = uniq(missing_recommended)
    missing_optional = uniq(missing_optional)
    fixable = uniq(fixable)

    # overall
    overall_ready = all(v.get("ready") for v in by_platform.values()) if by_platform else False
    hints: list[str] = []
    for cid in missing_required + missing_recommended:
        spec = next((s for s in DEP_CATALOG if s.id == cid), None)
        if spec:
            hints.extend(install_commands(spec))

    return {
        "ok": True,
        "platform": plat,
        "path": path,
        "host": {
            "system": py_platform.system(),
            "machine": py_platform.machine(),
            "python": sys.version.split()[0],
            "executable": sys.executable,
        },
        "platforms": by_platform,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "missing_optional": missing_optional,
        "fixable": fixable,
        "install_hints": uniq(hints),
        "ready": overall_ready,
        "summary": {
            "platforms": len(by_platform),
            "checks": len(all_checks),
            "missing": len(missing_required) + len(missing_recommended),
            "fixable": len(fixable),
        },
        "next_steps": _next_steps(missing_required, missing_recommended, fixable),
    }


def _next_steps(req: list[str], rec: list[str], fixable: list[str]) -> list[str]:
    steps: list[str] = []
    if fixable:
        steps.append(
            "Run: easy-rev doctor --fix"
            + (f" --only {','.join(fixable[:8])}" if fixable else "")
            + "   # or: easy-rev ai call doctor.fix -i '{}'"
        )
    if req:
        steps.append(f"Required missing: {', '.join(req)} — install before production RE")
    if rec:
        steps.append(f"Recommended missing: {', '.join(rec)} — static-only may still work")
    if not req and not rec:
        steps.append("Toolchain looks good for recommended paths")
    return steps


def fix_deps(
    ids: list[str] | None = None,
    *,
    platform: str | None = "all",
    allow_system: bool = False,
    dry_run: bool = False,
    timeout_s: float = 600.0,
) -> dict[str, Any]:
    """Install missing auto-fixable dependencies.

    Safety: only pip + known post_cmds unless allow_system (then brew when present).
    """
    # choose targets
    wanted = set(ids) if ids else set()
    report = preflight(platform or "all")
    if not wanted:
        wanted = set(report.get("fixable") or [])
    # also allow explicit ids even if currently present (reinstall path)
    results: list[dict[str, Any]] = []
    for spec in DEP_CATALOG:
        if spec.id not in wanted:
            continue
        if not _host_ok(spec):
            results.append({"id": spec.id, "ok": False, "skipped": True, "reason": "host mismatch"})
            continue
        det = detect_dep(spec)
        if det.get("present") and ids is None:
            results.append({"id": spec.id, "ok": True, "skipped": True, "reason": "already present"})
            continue
        if not spec.auto_fixable and not allow_system:
            results.append(
                {
                    "id": spec.id,
                    "ok": False,
                    "skipped": True,
                    "reason": "not auto_fixable without allow_system",
                    "install": install_commands(spec),
                }
            )
            continue

        actions: list[dict[str, Any]] = []
        cmds: list[list[str]] = []
        if spec.pip_extra:
            cmds.append([sys.executable, "-m", "pip", "install", f"easy-rev[{spec.pip_extra}]"])
        elif spec.pip_packages:
            cmds.append([sys.executable, "-m", "pip", "install", *spec.pip_packages])
        cmds.extend(list(spec.post_cmds))
        if allow_system and spec.brew and sys.platform == "darwin" and shutil.which("brew"):
            cmds.append(["brew", "install", spec.brew])

        if dry_run:
            results.append(
                {
                    "id": spec.id,
                    "ok": True,
                    "dry_run": True,
                    "commands": [" ".join(c) for c in cmds],
                }
            )
            continue

        ok_all = True
        for cmd in cmds:
            entry: dict[str, Any] = {"cmd": " ".join(cmd)}
            try:
                r = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                )
                entry["returncode"] = r.returncode
                entry["stdout_tail"] = (r.stdout or "")[-800:]
                entry["stderr_tail"] = (r.stderr or "")[-800:]
                if r.returncode != 0:
                    ok_all = False
            except Exception as e:  # noqa: BLE001
                entry["error"] = str(e)
                ok_all = False
            actions.append(entry)

        after = detect_dep(spec)
        results.append(
            {
                "id": spec.id,
                "ok": ok_all and bool(after.get("present")),
                "present_after": bool(after.get("present")),
                "actions": actions,
                "version": after.get("version") or after.get("version_line"),
            }
        )

    # re-run preflight
    after_pf = preflight(platform or "all")
    return {
        "ok": all(r.get("ok") or r.get("skipped") for r in results) if results else True,
        "fixed": [r["id"] for r in results if r.get("present_after") or (r.get("ok") and r.get("dry_run"))],
        "results": results,
        "preflight_after": {
            "ready": after_pf.get("ready"),
            "missing_required": after_pf.get("missing_required"),
            "missing_recommended": after_pf.get("missing_recommended"),
            "fixable": after_pf.get("fixable"),
            "platforms": {
                k: {"score": v.get("score"), "ready": v.get("ready"), "missing": v.get("missing")}
                for k, v in (after_pf.get("platforms") or {}).items()
            },
        },
    }


def readiness_for_path(platform: str, path: str) -> dict[str, Any]:
    """Preflight filtered to a RE capability path (e.g. browser, dynamic, static)."""
    pf = preflight(platform, path=path)
    return pf


def catalog_public() -> list[dict[str, Any]]:
    return [
        {
            **asdict(s),
            "install": install_commands(s),
        }
        for s in DEP_CATALOG
        if _host_ok(s)
    ]
