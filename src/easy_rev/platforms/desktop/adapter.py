"""Desktop RE adapter — static PE/Mach-O + Frida dynamic instrumentation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from easy_rev.core.platform import Platform, PlatformFamily, TargetSpec
from easy_rev.core.types import ArtifactKind, CaptureArtifact, ProbeResult
from easy_rev.platforms.base import PlatformAdapter


class DesktopAdapter(PlatformAdapter):
    family = PlatformFamily.DESKTOP
    platforms = (Platform.WINDOWS, Platform.MACOS)

    def __init__(self, platform: Platform = Platform.MACOS) -> None:
        self.platform = platform

    async def doctor(self) -> dict[str, Any]:
        from easy_rev.platforms.desktop.common.toolchain import probe_desktop_toolchain

        info = probe_desktop_toolchain(self.platform)
        info["platform"] = self.platform.value
        return info

    async def explore(self, target: TargetSpec, **kwargs: Any) -> ProbeResult:
        started = datetime.now(UTC)
        findings: dict[str, Any] = {}
        arts: list[CaptureArtifact] = []

        # 1) Static pass if binary present
        binary = target.binary or kwargs.get("binary")
        if binary:
            from easy_rev.platforms.desktop.common.static import analyze_binary

            static = await analyze_binary(binary, platform=self.platform)
            findings["static"] = static
            for p in static.get("artifact_paths") or []:
                arts.append(CaptureArtifact(kind=ArtifactKind.BINARY, path=p))

        # 2) Dynamic attach if process present
        process = target.process or kwargs.get("process")
        if process and kwargs.get("attach", True):
            from easy_rev.platforms.desktop.common.frida_session import explore_process

            dyn = await explore_process(
                process,
                platform=self.platform,
                scripts=kwargs.get("scripts") or [],
                duration_s=float(kwargs.get("duration_s") or 5.0),
            )
            findings["dynamic"] = dyn
            if dyn.get("log_path"):
                arts.append(
                    CaptureArtifact(kind=ArtifactKind.FRIDA_LOG, path=dyn["log_path"])
                )

        if not binary and not process:
            return ProbeResult(
                ok=False,
                platform=self.platform.value,
                target=target.label(),
                error="desktop explore requires binary= and/or process=",
                started_at=started,
                finished_at=datetime.now(UTC),
            )

        # Recommendation heuristic
        recommendation = "static"
        risk = "low"
        dyn = findings.get("dynamic") or {}
        static = findings.get("static") or {}
        if dyn.get("attached"):
            recommendation = "frida"
            risk = "medium"
        if static.get("packing_suspected") or static.get("anti_debug"):
            risk = "high"
            recommendation = "frida+manual"

        return ProbeResult(
            ok=True,
            platform=self.platform.value,
            target=target.label(),
            recommendation=recommendation,
            risk=risk,
            artifacts=arts,
            findings=findings,
            started_at=started,
            finished_at=datetime.now(UTC),
        )

    async def capture(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        process = target.process or kwargs.get("process")
        if not process:
            return {"ok": False, "error": "process required for desktop capture"}
        from easy_rev.platforms.desktop.common.frida_session import capture_process

        result = await capture_process(
            process,
            platform=self.platform,
            scripts=kwargs.get("scripts") or [],
            duration_s=float(kwargs.get("duration_s") or 10.0),
            host=kwargs.get("host"),
        )
        # ok already set by dynamic_result; dry_run is not "attached success"
        if "status" not in result:
            if result.get("attached"):
                result["status"] = "attached"
            elif result.get("dry_run"):
                result["status"] = "dry_run"
            else:
                result["status"] = "error"
                result["ok"] = False
        return result

    async def analyze(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        binary = target.binary or kwargs.get("binary")
        if not binary:
            return {"ok": False, "error": "binary path required", "platform": self.platform.value}
        from easy_rev.platforms.desktop.common.static import analyze_binary

        result = await analyze_binary(binary, platform=self.platform)
        if "ok" not in result:
            result["ok"] = not bool(result.get("error"))
        return result
