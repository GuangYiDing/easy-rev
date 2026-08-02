"""Browser network traffic capture (Playwright/Camoufox page events)."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Playwright resource types we care about for RE
DEFAULT_RESOURCE_TYPES = frozenset(
    {
        "xhr",
        "fetch",
        "document",
        "websocket",
        "other",
        "script",
    }
)

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)


@dataclass
class NetworkEntry:
    """One request/response pair (or request-only if no response yet)."""

    id: int
    method: str
    url: str
    resource_type: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    post_data: str | None = None
    status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None
    response_body_truncated: bool = False
    response_body_bytes: int = 0
    content_type: str = ""
    timing_ms: float | None = None
    from_service_worker: bool = False
    failed: bool = False
    failure_text: str | None = None
    started_at: float = field(default_factory=time.time)
    # classification filled later
    score: int = 0
    tags: list[str] = field(default_factory=list)
    api_summary: str | None = None

    def to_dict(self, *, redact_secrets: bool = True, include_body: bool = True) -> dict[str, Any]:
        d = asdict(self)
        if redact_secrets:
            d["request_headers"] = _redact_headers(self.request_headers)
            d["response_headers"] = _redact_headers(self.response_headers)
            if self.post_data and _looks_sensitive(self.post_data):
                d["post_data"] = _redact_body_preview(self.post_data)
        if not include_body:
            d.pop("response_body", None)
            d.pop("post_data", None)
        return d


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_NAMES:
            out[k] = f"<redacted len={len(v)}>"
        else:
            out[k] = v
    return out


def _looks_sensitive(text: str) -> bool:
    lower = text.lower()
    return any(
        x in lower
        for x in ("password", "passwd", "secret", "token", "authorization", "credit_card")
    )


def _redact_body_preview(text: str, limit: int = 400) -> str:
    """Keep structure hints but mask password-like values when possible."""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            redacted = {}
            for k, v in data.items():
                kl = str(k).lower()
                if any(x in kl for x in ("pass", "secret", "token", "auth", "pwd")):
                    redacted[k] = "<redacted>"
                else:
                    redacted[k] = v
            return json.dumps(redacted, ensure_ascii=False)[:limit]
    except Exception:  # noqa: BLE001
        pass
    return text[:limit] + ("…" if len(text) > limit else "")


def _normalize_headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    # Playwright Headers array-like
    try:
        return {str(k): str(v) for k, v in dict(raw).items()}
    except Exception:  # noqa: BLE001
        return {}


def _header_get(headers: dict[str, str], name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


class NetworkCapture:
    """Attach to a Playwright-like page and record request/response pairs."""

    def __init__(
        self,
        *,
        capture_bodies: bool = True,
        max_body_bytes: int = 64_000,
        max_entries: int = 250,
        resource_types: set[str] | frozenset[str] | None = None,
        url_includes: list[str] | None = None,
        url_excludes: list[str] | None = None,
        methods: list[str] | None = None,
        redact_secrets: bool = True,
    ) -> None:
        self.capture_bodies = capture_bodies
        self.max_body_bytes = max_body_bytes
        self.max_entries = max_entries
        self.resource_types = set(resource_types) if resource_types else set(DEFAULT_RESOURCE_TYPES)
        self.url_includes = [u.lower() for u in (url_includes or [])]
        self.url_excludes = [u.lower() for u in (url_excludes or [])]
        self.methods = {m.upper() for m in methods} if methods else None
        self.redact_secrets = redact_secrets

        self.entries: list[NetworkEntry] = []
        self._by_request_id: dict[int, NetworkEntry] = {}
        self._seq = 0
        self._attached = False
        self._page: Any = None
        self._pending_body_tasks: list[Any] = []
        # WebSocket frames: [{url, direction, payload, opcode, ts}]
        self.websocket_frames: list[dict[str, Any]] = []
        self._ws_urls: set[str] = set()
        self.max_ws_frames = 200
        self.max_ws_payload = 4000

    def _next_id(self) -> int:
        self._seq += 1
        return self._seq

    def _url_allowed(self, url: str) -> bool:
        ul = url.lower()
        if self.url_excludes and any(x in ul for x in self.url_excludes):
            return False
        if self.url_includes and not any(x in ul for x in self.url_includes):
            return False
        return True

    def _type_allowed(self, resource_type: str) -> bool:
        if not self.resource_types:
            return True
        rt = (resource_type or "other").lower()
        # Always keep xhr/fetch if filter is default-ish; otherwise strict
        return rt in self.resource_types or rt in {"xhr", "fetch"}

    def attach(self, page: Any) -> None:
        """Register listeners on page. Safe to call once."""
        if self._attached:
            return
        self._page = page
        on = getattr(page, "on", None)
        if not callable(on):
            logger.warning("page has no .on(); network capture disabled")
            return

        def on_request(request: Any) -> None:
            try:
                self._handle_request(request)
            except Exception:  # noqa: BLE001
                logger.debug("request handler error", exc_info=True)

        def on_response(response: Any) -> None:
            try:
                self._handle_response(response)
            except Exception:  # noqa: BLE001
                logger.debug("response handler error", exc_info=True)

        def on_request_failed(request: Any) -> None:
            try:
                self._handle_request_failed(request)
            except Exception:  # noqa: BLE001
                logger.debug("requestfailed handler error", exc_info=True)

        on("request", on_request)
        on("response", on_response)
        try:
            on("requestfailed", on_request_failed)
        except Exception:  # noqa: BLE001
            pass

        def on_websocket(ws: Any) -> None:
            try:
                self._handle_websocket(ws)
            except Exception:  # noqa: BLE001
                logger.debug("websocket handler error", exc_info=True)

        try:
            on("websocket", on_websocket)
        except Exception:  # noqa: BLE001
            pass
        self._attached = True

    def _handle_websocket(self, ws: Any) -> None:
        url = str(getattr(ws, "url", "") or "")
        if not self._url_allowed(url):
            return
        self._ws_urls.add(url)
        # Also record a synthetic network entry for ranking
        if len(self.entries) < self.max_entries:
            entry = NetworkEntry(
                id=self._next_id(),
                method="WS",
                url=url,
                resource_type="websocket",
            )
            self.entries.append(entry)

        def _frame(direction: str, payload: Any) -> None:
            if len(self.websocket_frames) >= self.max_ws_frames:
                return
            text: str
            if isinstance(payload, (bytes, bytearray)):
                try:
                    text = bytes(payload).decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    text = f"<binary {len(payload)} bytes>"
            else:
                text = str(payload)
            if len(text) > self.max_ws_payload:
                text = text[: self.max_ws_payload] + "…"
            self.websocket_frames.append(
                {
                    "url": url,
                    "direction": direction,
                    "payload": text,
                    "ts": time.time(),
                }
            )

        try:
            ws.on("framesent", lambda payload: _frame("sent", payload))
            ws.on("framereceived", lambda payload: _frame("received", payload))
            ws.on(
                "close",
                lambda: self.websocket_frames.append(
                    {"url": url, "direction": "close", "payload": "", "ts": time.time()}
                ),
            )
        except Exception:  # noqa: BLE001
            logger.debug("ws frame hooks failed", exc_info=True)

    def websockets_summary(self, *, limit: int = 40) -> dict[str, Any]:
        frames = self.websocket_frames[-limit:]
        return {
            "urls": sorted(self._ws_urls),
            "frame_count": len(self.websocket_frames),
            "frames": frames,
        }

    def _handle_request(self, request: Any) -> None:
        if len(self.entries) >= self.max_entries:
            return
        url = str(getattr(request, "url", "") or "")
        method = str(getattr(request, "method", "GET") or "GET").upper()
        resource_type = str(getattr(request, "resource_type", "") or "").lower()
        if not self._url_allowed(url):
            return
        if not self._type_allowed(resource_type):
            return
        if self.methods and method not in self.methods:
            return

        headers = _normalize_headers(getattr(request, "headers", None))
        post_data = None
        try:
            post_data = getattr(request, "post_data", None)
            if callable(post_data):
                post_data = post_data()
            if post_data is not None:
                post_data = str(post_data)
                if len(post_data) > self.max_body_bytes:
                    post_data = post_data[: self.max_body_bytes] + "…"
        except Exception:  # noqa: BLE001
            post_data = None

        entry = NetworkEntry(
            id=self._next_id(),
            method=method,
            url=url,
            resource_type=resource_type or "other",
            request_headers=headers,
            post_data=post_data,
        )
        self.entries.append(entry)
        # Map by object id for response correlation
        self._by_request_id[id(request)] = entry

    def _handle_response(self, response: Any) -> None:
        request = getattr(response, "request", None)
        entry: NetworkEntry | None = None
        if request is not None:
            entry = self._by_request_id.get(id(request))
        if entry is None:
            # Late response without request match — create shell if allowed
            url = str(getattr(response, "url", "") or "")
            if not self._url_allowed(url) or len(self.entries) >= self.max_entries:
                return
            entry = NetworkEntry(
                id=self._next_id(),
                method="GET",
                url=url,
                resource_type="other",
            )
            self.entries.append(entry)

        try:
            entry.status = int(getattr(response, "status", 0) or 0)
        except Exception:  # noqa: BLE001
            entry.status = None
        entry.response_headers = _normalize_headers(getattr(response, "headers", None))
        entry.content_type = _header_get(entry.response_headers, "content-type")
        entry.timing_ms = round((time.time() - entry.started_at) * 1000, 1)

        if self.capture_bodies:
            # Body read must be async in Playwright — schedule via create_task if loop running
            try:
                import asyncio

                loop = asyncio.get_running_loop()
                task = loop.create_task(self._fill_body(entry, response))
                self._pending_body_tasks.append(task)
            except RuntimeError:
                # No running loop; skip body
                pass

    async def _fill_body(self, entry: NetworkEntry, response: Any) -> None:
        try:
            ct = (entry.content_type or "").lower()
            # Skip multipart / streaming blobs — Firefox may throw
            # "Separator is not found, and chunk exceed the limit" on body().
            if any(
                x in ct
                for x in (
                    "multipart/",
                    "octet-stream",
                    "image/",
                    "audio/",
                    "video/",
                    "font/",
                    "wasm",
                )
            ):
                entry.response_body = f"<skipped content-type={entry.content_type}>"
                return
            body = await response.body()
            if body is None:
                return
            entry.response_body_bytes = len(body)
            if len(body) > self.max_body_bytes:
                entry.response_body_truncated = True
                body = body[: self.max_body_bytes]
            # Prefer text for JSON / text types
            if any(x in ct for x in ("json", "text", "javascript", "xml", "html", "urlencoded")):
                entry.response_body = body.decode("utf-8", errors="replace")
            else:
                # Still try utf-8; if mostly binary, show hex head
                text = body.decode("utf-8", errors="replace")
                if "\x00" in text[:200]:
                    entry.response_body = f"<binary {entry.response_body_bytes} bytes>"
                else:
                    entry.response_body = text
        except Exception as e:  # noqa: BLE001
            entry.response_body = None
            entry.failure_text = entry.failure_text or f"body_read: {e}"

    def _handle_request_failed(self, request: Any) -> None:
        entry = self._by_request_id.get(id(request))
        if not entry:
            return
        entry.failed = True
        try:
            failure = getattr(request, "failure", None)
            if callable(failure):
                failure = failure()
            if isinstance(failure, dict):
                entry.failure_text = str(failure.get("errorText") or failure)
            elif failure:
                entry.failure_text = str(failure)
        except Exception:  # noqa: BLE001
            entry.failure_text = "request failed"

    async def flush(self, timeout_s: float = 2.0) -> None:
        """Wait for pending body reads."""
        if not self._pending_body_tasks:
            return
        import asyncio

        try:
            await asyncio.wait_for(
                asyncio.gather(*self._pending_body_tasks, return_exceptions=True),
                timeout=timeout_s,
            )
        except TimeoutError:
            logger.debug("network body flush timed out")
        self._pending_body_tasks.clear()

    def filtered_entries(
        self,
        *,
        api_only: bool = False,
        min_score: int = 0,
    ) -> list[NetworkEntry]:
        from easy_rev.platforms.web.re.classify import classify_entry

        out: list[NetworkEntry] = []
        for e in self.entries:
            classify_entry(e)
            if api_only and e.score < max(min_score, 3):
                continue
            if e.score < min_score:
                continue
            out.append(e)
        return out

    def to_list(
        self,
        *,
        api_only: bool = False,
        min_score: int = 0,
        include_body: bool = True,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        entries = self.filtered_entries(api_only=api_only, min_score=min_score)
        # Highest score first, then chronological id
        entries = sorted(entries, key=lambda e: (-e.score, e.id))
        if limit is not None:
            entries = entries[:limit]
        return [
            e.to_dict(redact_secrets=self.redact_secrets, include_body=include_body) for e in entries
        ]

    def export_har_like(self) -> dict[str, Any]:
        """W3C HAR 1.2 document (Chrome/Charles compatible)."""
        from easy_rev.platforms.web.re.har_export import capture_to_har

        return capture_to_har(self)

    def summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        hosts: dict[str, int] = {}
        for e in self.entries:
            by_type[e.resource_type or "other"] = by_type.get(e.resource_type or "other", 0) + 1
            st = str(e.status if e.status is not None else "pending")
            by_status[st] = by_status.get(st, 0) + 1
            try:
                host = urlparse(e.url).netloc or "?"
            except Exception:  # noqa: BLE001
                host = "?"
            hosts[host] = hosts.get(host, 0) + 1
        return {
            "total": len(self.entries),
            "by_resource_type": by_type,
            "by_status": by_status,
            "top_hosts": sorted(hosts.items(), key=lambda x: -x[1])[:15],
        }
