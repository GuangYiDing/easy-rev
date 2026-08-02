"""Shared types, paths, and platform abstractions."""

from easy_rev.core.platform import Platform, PlatformFamily, TargetSpec
from easy_rev.core.types import (
    ArtifactKind,
    BrowserProfile,
    CaptureArtifact,
    ProbeResult,
    ProxyEndpoint,
    SessionInfo,
    TaskStatus,
)

__all__ = [
    "Platform",
    "PlatformFamily",
    "TargetSpec",
    "ArtifactKind",
    "BrowserProfile",
    "CaptureArtifact",
    "ProbeResult",
    "ProxyEndpoint",
    "SessionInfo",
    "TaskStatus",
]
