"""Mobile RE adapter — APK/IPA static + Frida over USB/remote."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from easy_rev.core.platform import Platform, PlatformFamily, TargetSpec
from easy_rev.core.types import ArtifactKind, CaptureArtifact, ProbeResult
from easy_rev.platforms.base import PlatformAdapter


class MobileAdapter(PlatformAdapter):
    family = PlatformFamily.MOBILE
    platforms = (Platform.ANDROID, Platform.IOS)

    def __init__(self, platform: Platform = Platform.ANDROID) -> None:
        self.platform = platform

    async def doctor(self) -> dict[str, Any]:
        from easy_rev.platforms.mobile.common.toolchain import probe_mobile_toolchain

        info = probe_mobile_toolchain(self.platform)
        info["platform"] = self.platform.value
        return info

    async def explore(self, target: TargetSpec, **kwargs: Any) -> ProbeResult:
        started = datetime.now(UTC)
        findings: dict[str, Any] = {}
        arts: list[CaptureArtifact] = []

        binary = target.binary or kwargs.get("binary")
        package = target.package or kwargs.get("package")
        device = target.device or kwargs.get("device")

        if binary:
            from easy_rev.platforms.mobile.common.static import analyze_package

            static = await analyze_package(binary, platform=self.platform)
            findings["static"] = static
            for p in static.get("artifact_paths") or []:
                arts.append(CaptureArtifact(kind=ArtifactKind.BINARY, path=p))
            if not package and static.get("package"):
                package = static["package"]

        if package and kwargs.get("attach", True):
            from easy_rev.platforms.mobile.common.frida_session import explore_app

            dyn = await explore_app(
                package,
                platform=self.platform,
                device=device,
                scripts=kwargs.get("scripts") or [],
                spawn=bool(kwargs.get("spawn", True)),
                duration_s=float(kwargs.get("duration_s") or 5.0),
            )
            findings["dynamic"] = dyn
            if dyn.get("log_path"):
                arts.append(
                    CaptureArtifact(kind=ArtifactKind.FRIDA_LOG, path=dyn["log_path"])
                )

        if not binary and not package:
            return ProbeResult(
                ok=False,
                platform=self.platform.value,
                target=target.label(),
                error="mobile explore requires binary= (apk/ipa) and/or package=",
                started_at=started,
                finished_at=datetime.now(UTC),
            )

        recommendation = "static"
        risk = "low"
        dyn = findings.get("dynamic") or {}
        static = findings.get("static") or {}
        if dyn.get("attached"):
            recommendation = "frida"
            risk = "medium"
        if static.get("obfuscated") or static.get("ssl_pinning_hints"):
            risk = "high"
            recommendation = "frida+unpin"

        return ProbeResult(
            ok=True,
            platform=self.platform.value,
            target=package or target.label(),
            recommendation=recommendation,
            risk=risk,
            artifacts=arts,
            findings=findings,
            started_at=started,
            finished_at=datetime.now(UTC),
        )

    async def capture(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        package = target.package or kwargs.get("package")
        if not package:
            return {"ok": False, "error": "package required for mobile capture"}
        from easy_rev.platforms.mobile.common.frida_session import capture_app

        result = await capture_app(
            package,
            platform=self.platform,
            device=target.device or kwargs.get("device"),
            scripts=kwargs.get("scripts") or [],
            spawn=bool(kwargs.get("spawn", True)),
            duration_s=float(kwargs.get("duration_s") or 10.0),
        )
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
            return {"ok": False, "error": "apk/ipa path required", "platform": self.platform.value}
        from easy_rev.platforms.mobile.common.static import analyze_package

        result = await analyze_package(binary, platform=self.platform)
        if "ok" not in result:
            result["ok"] = not bool(result.get("error"))
        return result
