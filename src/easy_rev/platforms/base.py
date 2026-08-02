"""Abstract platform adapter — every RE surface implements this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from easy_rev.core.platform import Platform, PlatformFamily, TargetSpec
from easy_rev.core.types import ProbeResult


class PlatformAdapter(ABC):
    """Commercial reverse-engineering surface for one platform family."""

    family: PlatformFamily
    platforms: tuple[Platform, ...]

    @abstractmethod
    async def doctor(self) -> dict[str, Any]:
        """Report toolchains / runtimes available for this platform."""

    @abstractmethod
    async def explore(self, target: TargetSpec, **kwargs: Any) -> ProbeResult:
        """One-shot: attach/analyze target and return structured findings."""

    @abstractmethod
    async def capture(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        """Capture runtime traffic / hooks / dumps."""

    async def analyze(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        """Static or post-capture analysis (optional override)."""
        return {"ok": True, "message": "analyze not specialized for this platform"}

    async def session_start(self, target: TargetSpec, **kwargs: Any) -> dict[str, Any]:
        """Start a persistent RE session (optional)."""
        return {"ok": False, "error": "session not supported on this platform adapter"}


def get_adapter(platform: Platform | str) -> PlatformAdapter:
    """Resolve a concrete adapter from platform name."""
    if isinstance(platform, str):
        platform = Platform(platform.lower())

    if platform is Platform.WEB:
        from easy_rev.platforms.web.adapter import WebAdapter

        return WebAdapter()
    if platform in {Platform.WINDOWS, Platform.MACOS}:
        from easy_rev.platforms.desktop.adapter import DesktopAdapter

        return DesktopAdapter(platform=platform)
    if platform in {Platform.ANDROID, Platform.IOS}:
        from easy_rev.platforms.mobile.adapter import MobileAdapter

        return MobileAdapter(platform=platform)
    raise ValueError(f"unsupported platform: {platform}")
