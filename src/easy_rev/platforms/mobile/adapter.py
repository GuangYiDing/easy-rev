"""Mobile RE adapter — APK/IPA static + Frida over USB/remote."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from easy_rev.core.platform import Platform, PlatformFamily, TargetSpec
from easy_rev.core.result import derive_status
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
        next_steps: list[str] = []
        blocking: list[str] = []

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
            if static.get("error"):
                blocking.append(f"static:{static.get('error')}")

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
            if dyn.get("dry_run") or dyn.get("status") == "dry_run":
                blocking.append("missing:frida")
                next_steps.append("pip install 'easy-rev[frida]' and ensure frida-server on device")
            elif dyn.get("error") or dyn.get("status") == "error":
                blocking.append(f"dynamic:{dyn.get('error') or 'attach_failed'}")
                if dyn.get("hint"):
                    next_steps.append(str(dyn["hint"]))

        if not binary and not package:
            return ProbeResult(
                ok=False,
                platform=self.platform.value,
                target=target.label(),
                status="error",
                confidence="none",
                error="mobile explore requires binary= (apk/ipa) and/or package=",
                blocking_issues=["missing:binary_or_package"],
                next_steps=[
                    "Pass binary=./app.apk for static analysis",
                    "Pass package=com.example for Frida spawn/attach",
                ],
                started_at=started,
                finished_at=datetime.now(UTC),
            ).ensure_status_fields()

        recommendation = "static"
        risk = "low"
        dyn = findings.get("dynamic") or {}
        static = findings.get("static") or {}
        if dyn.get("attached"):
            recommendation = "frida"
            risk = "medium"
            next_steps.append("Load mobile scripts (ssl_pinning/crypto/network) via pack hooks or frida.session")
        if static.get("obfuscated") or static.get("ssl_pinning_hints"):
            risk = "high"
            recommendation = "frida+unpin"
            next_steps.append("Pinning/obfuscation hints — customize ssl_pinning.js for the target stack")
        if binary and not package:
            next_steps.append("Use package from static report (or mobile.apps) then re-run with attach")
        if package and not binary:
            next_steps.append("Optional: pass binary=apk/ipa for static context")

        status = derive_status(has_static=bool(binary and findings.get("static")), dyn=dyn)
        hint = dyn.get("hint") if isinstance(dyn, dict) else None
        if status == "static" and not hint:
            hint = "static-only path; dynamic not attached"
        if status == "dry_run" and not hint:
            hint = "Frida missing or dry-run — not attached"

        return ProbeResult(
            ok=status != "error",
            platform=self.platform.value,
            target=package or target.label(),
            status=status,
            hint=hint,
            next_steps=next_steps,
            blocking_issues=blocking,
            recommendation=recommendation,
            risk=risk,
            artifacts=arts,
            findings=findings,
            error=dyn.get("error") if status == "error" else None,
            started_at=started,
            finished_at=datetime.now(UTC),
        ).ensure_status_fields()

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
