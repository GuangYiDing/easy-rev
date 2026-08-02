"""Platform taxonomy and target descriptors for multi-end reverse engineering."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PlatformFamily(StrEnum):
    """Top-level reverse-engineering family."""

    WEB = "web"
    DESKTOP = "desktop"
    MOBILE = "mobile"


class Platform(StrEnum):
    """Concrete runtime target."""

    WEB = "web"
    WINDOWS = "windows"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"

    @property
    def family(self) -> PlatformFamily:
        if self is Platform.WEB:
            return PlatformFamily.WEB
        if self in {Platform.WINDOWS, Platform.MACOS}:
            return PlatformFamily.DESKTOP
        return PlatformFamily.MOBILE


class TargetSpec(BaseModel):
    """Unified description of a reverse-engineering target."""

    platform: Platform
    # Human-readable name
    name: str | None = None
    # Web
    url: str | None = None
    # Desktop / mobile process or package
    process: str | None = None  # process name or PID string
    package: str | None = None  # Android package / iOS bundle id
    # Binary path (PE / Mach-O / APK / IPA / dex)
    binary: str | None = None
    # Device selector (ADB serial / iOS UDID)
    device: str | None = None
    # Free-form extra
    meta: dict[str, Any] = Field(default_factory=dict)

    def label(self) -> str:
        if self.name:
            return self.name
        if self.url:
            return self.url
        if self.package:
            return self.package
        if self.process:
            return self.process
        if self.binary:
            return self.binary
        return f"{self.platform.value}-target"
