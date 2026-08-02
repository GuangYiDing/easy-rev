from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ArtifactKind(StrEnum):
    CAPTURE = "capture"
    HAR = "har"
    NETWORK = "network"
    HOOKS = "hooks"
    CRYPTO = "crypto"
    BINARY = "binary"
    DISASM = "disasm"
    STRINGS = "strings"
    FRIDA_LOG = "frida_log"
    MEMORY_DUMP = "memory_dump"
    SCREENSHOT = "screenshot"
    PACK = "pack"
    REPORT = "report"
    OTHER = "other"


class ProxyEndpoint(BaseModel):
    server: str  # http://host:port or socks5://host:port
    username: str | None = None
    password: str | None = None
    country: str | None = None


class BrowserProfile(BaseModel):
    """Web browser session profile (Camoufox / CDP attach)."""

    headless: bool = True
    locale: str = "en-US"
    timezone_id: str | None = None
    proxy: ProxyEndpoint | None = None
    humanize: bool = True
    geoip: bool = True
    # CDP attach (user Chrome / Edge)
    cdp_url: str | None = None
    cdp_target_url: str | None = None
    cdp_target_index: int | None = None
    cdp_new_page_url: str | None = None


class AccountProfile(BaseModel):
    """Synthetic identity for web form auto-fill during RE."""

    email: str
    password: str
    username: str | None = None
    phone: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class CaptureArtifact(BaseModel):
    """A single reverse-engineering artifact on disk or in memory."""

    kind: ArtifactKind
    path: str | None = None
    summary: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ProbeResult(BaseModel):
    """Normalized result of a platform probe / explore run."""

    ok: bool = True
    platform: str
    target: str
    # Unified dynamic/static path status (see easy_rev.core.result)
    status: str | None = None  # attached|dry_run|error|static|offline|degraded
    attached: bool | None = None
    dry_run: bool | None = None
    degraded: bool | None = None
    confidence: str | None = None  # high|medium|low|none
    hint: str | None = None
    next_steps: list[str] = Field(default_factory=list)
    blocking_issues: list[str] = Field(default_factory=list)
    recommendation: str | None = None  # e.g. protocol | hybrid | frida | static
    risk: str | None = None
    artifacts: list[CaptureArtifact] = Field(default_factory=list)
    findings: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    # Common explore paths (also mirrored under findings when useful)
    capture_path: str | None = None
    har_path: str | None = None
    pack_path: str | None = None

    def ensure_status_fields(self) -> ProbeResult:
        """Fill status/attached/dry_run/degraded/confidence from status or ok/error."""
        status = self.status
        if not status:
            if self.error and not self.ok:
                status = "error"
            elif self.ok:
                status = "static"
            else:
                status = "error"
            self.status = status
        if self.attached is None:
            self.attached = status == "attached"
        if self.dry_run is None:
            self.dry_run = status == "dry_run"
        if self.degraded is None:
            self.degraded = status in {"dry_run", "offline", "degraded"}
        if self.confidence is None:
            if status == "error" or (self.error and not self.ok):
                self.confidence = "none"
            elif status == "attached":
                self.confidence = "high"
            elif status == "static":
                self.confidence = "medium" if self.findings or self.artifacts else "low"
            else:
                self.confidence = "low"
        if status == "error":
            self.ok = False
        elif self.error is None and status in {
            "attached",
            "dry_run",
            "static",
            "offline",
            "degraded",
        }:
            self.ok = True
        return self

    def to_envelope(self) -> dict[str, Any]:
        """Agent-facing dict with stable top-level status fields."""
        self.ensure_status_fields()
        data = self.model_dump(mode="json")
        # Keep empty findings/artifacts lists; drop only None
        return {k: v for k, v in data.items() if v is not None}


class SessionInfo(BaseModel):
    """Persistent RE session metadata."""

    session_id: str
    platform: str
    target: str
    status: TaskStatus = TaskStatus.RUNNING
    created_at: datetime = Field(default_factory=utc_now)
    meta: dict[str, Any] = Field(default_factory=dict)
