"""Local HTTP bridge for the Easy-Rev Chrome extension (localhost only).

Extension posts page snapshots + Network CDP events; we convert to capture JSON
compatible with pack.from_capture / re.analyze / re.diagnose.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from easy_rev.core.paths import artifacts_dir
from easy_rev.platforms.web.re.classify import api_candidates_as_dicts, suggest_http_steps
from easy_rev.platforms.web.re.network import NetworkEntry

logger = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18765

_STATE: dict[str, Any] = {
    "server": None,
    "thread": None,
    "last_capture_path": None,
    "last_result": None,
    "started_at": None,
    "token": None,
    "count": 0,
}


def _cors_headers(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, X-Easy-Rev-Token")


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length) if length else b"{}"
    try:
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _check_token(handler: BaseHTTPRequestHandler) -> bool:
    expected = _STATE.get("token")
    if not expected:
        return True
    got = handler.headers.get("X-Easy-Rev-Token") or ""
    return str(got) == str(expected)


def network_events_to_entries(events: list[dict[str, Any]]) -> list[NetworkEntry]:
    """Convert chrome.debugger Network.* events into NetworkEntry list."""
    by_id: dict[str, NetworkEntry] = {}
    seq = 0
    extras: list[NetworkEntry] = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        method = ev.get("method") or ""
        params = ev.get("params") or {}
        if method == "EasyRev.navigation":
            # OAuth redirects / full document navigations captured outside debugger
            seq += 1
            url = str(params.get("url") or params.get("redirectUrl") or params.get("nextUrl") or "")
            if not url:
                continue
            headers = params.get("headers") or {}
            if not isinstance(headers, dict):
                headers = {}
            status = params.get("status")
            if status is None:
                status = params.get("statusCode")
            try:
                status_i = int(status) if status is not None else None
            except Exception:  # noqa: BLE001
                status_i = None
            extras.append(
                NetworkEntry(
                    id=seq,
                    method="GET",
                    url=url,
                    resource_type="document",
                    status=status_i,
                    request_headers={},
                    response_headers={str(k): str(v) for k, v in headers.items()},
                    started_at=time.time(),
                    tags=["navigation", str(params.get("phase") or "nav")],
                )
            )
            # also keep redirect target if present and distinct
            nxt = str(params.get("redirectUrl") or params.get("nextUrl") or "")
            if nxt and nxt != url:
                seq += 1
                extras.append(
                    NetworkEntry(
                        id=seq,
                        method="GET",
                        url=nxt,
                        resource_type="document",
                        started_at=time.time(),
                        tags=["navigation", "redirect-target"],
                    )
                )
            continue
        if method == "Network.requestWillBeSent":
            req = params.get("request") or {}
            rid = str(params.get("requestId") or "")
            # Preserve intermediate redirect responses (form login 302 chains)
            redir = params.get("redirectResponse")
            if isinstance(redir, dict) and redir.get("url"):
                seq += 1
                try:
                    st = int(redir.get("status") or 0) or None
                except Exception:  # noqa: BLE001
                    st = None
                extras.append(
                    NetworkEntry(
                        id=seq,
                        method="GET",
                        url=str(redir.get("url") or ""),
                        resource_type=str(params.get("type") or "document").lower(),
                        status=st,
                        response_headers={
                            str(k): str(v) for k, v in (redir.get("headers") or {}).items()
                        },
                        started_at=time.time(),
                        tags=["redirectResponse"],
                    )
                )
            seq += 1
            url = str(req.get("url") or "")
            entry = NetworkEntry(
                id=seq,
                method=str(req.get("method") or "GET").upper(),
                url=url,
                resource_type=str(params.get("type") or "other").lower(),
                request_headers={str(k): str(v) for k, v in (req.get("headers") or {}).items()},
                post_data=req.get("postData"),
                started_at=time.time(),
            )
            # Map Chrome types
            rt = entry.resource_type
            if rt in {"xhr", "fetch"}:
                entry.resource_type = rt
            elif "websocket" in rt:
                entry.resource_type = "websocket"
            by_id[rid] = entry
        elif method == "Network.responseReceived":
            rid = str(params.get("requestId") or "")
            resp = params.get("response") or {}
            entry = by_id.get(rid)
            if not entry:
                continue
            try:
                entry.status = int(resp.get("status") or 0)
            except Exception:  # noqa: BLE001
                entry.status = None
            entry.response_headers = {
                str(k): str(v) for k, v in (resp.get("headers") or {}).items()
            }
            entry.content_type = str(resp.get("mimeType") or "")
            # refine type from mime
            if "json" in entry.content_type and entry.resource_type not in {"xhr", "fetch"}:
                entry.resource_type = "xhr"
        elif method == "Network.loadingFinished":
            rid = str(params.get("requestId") or "")
            entry = by_id.get(rid)
            if entry and params.get("encodedDataLength") is not None:
                try:
                    entry.response_body_bytes = int(params.get("encodedDataLength") or 0)
                except Exception:  # noqa: BLE001
                    pass
        elif method == "Network.loadingFailed":
            rid = str(params.get("requestId") or "")
            entry = by_id.get(rid)
            if entry:
                entry.failed = True
                entry.failure_text = str(params.get("errorText") or "failed")

    # Attach response bodies if extension included them
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        if ev.get("method") != "EasyRev.responseBody":
            continue
        params = ev.get("params") or {}
        rid = str(params.get("requestId") or "")
        entry = by_id.get(rid)
        if entry and params.get("body") is not None:
            body = str(params.get("body"))
            if params.get("base64Encoded"):
                try:
                    import base64

                    body = base64.b64decode(body).decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    pass
            # cap
            if len(body) > 64_000:
                entry.response_body = body[:64_000] + "…"
                entry.response_body_truncated = True
            else:
                entry.response_body = body
            entry.response_body_bytes = entry.response_body_bytes or len(body)

    entries = list(by_id.values()) + extras
    entries.sort(key=lambda e: getattr(e, "id", 0) or 0)
    return entries


def build_capture_from_extension(payload: dict[str, Any]) -> dict[str, Any]:
    """Build site.capture-compatible document from extension payload (full RE parity)."""
    from easy_rev.platforms.web.re.extension_full import enrich_extension_capture

    url = str(payload.get("url") or "")
    title = payload.get("title")
    events = payload.get("network_events") or payload.get("events") or []
    entries = network_events_to_entries(list(events))
    apis = api_candidates_as_dicts(entries, min_score=3, limit=50, redact_secrets=True)
    suggested = suggest_http_steps(apis, max_steps=10)

    cookies = payload.get("cookies") or []
    storage = payload.get("storage") or {}
    html = payload.get("html") or payload.get("html_snippet") or ""
    if isinstance(html, str) and len(html) > 20_000:
        html = html[:20_000] + "…"

    notes = list(payload.get("notes") or [])
    notes.append("source=chrome_extension")
    if payload.get("tab_id") is not None:
        notes.append(f"tab_id={payload.get('tab_id')}")
    if payload.get("page_hooks") or payload.get("hooks_dump"):
        notes.append("page_hooks+crypto included (near-camoufox parity)")

    doc: dict[str, Any] = {
        "url": url,
        "started_url": url,
        "engine": "chrome-extension",
        "title": title,
        "network_summary": {
            "total": len(entries),
            "by_resource_type": _count_by(entries, "resource_type"),
            "by_status": _count_status(entries),
        },
        "apis": apis,
        "network": [
            e.to_dict(redact_secrets=True, include_body=False) for e in entries[:100]
        ],
        "suggested_http_steps": suggested,
        "storage": {
            "cookies_compact": [
                {
                    "name": c.get("name"),
                    "value": str(c.get("value") or "")[:120],
                    "domain": c.get("domain"),
                    "path": c.get("path"),
                }
                for c in cookies
                if isinstance(c, dict)
            ][:80],
            "localStorage": storage.get("localStorage") or {},
            "sessionStorage": storage.get("sessionStorage") or {},
        },
        "dom": {
            "title": title,
            "url": url,
            "html_snippet": html[:8000] if html else "",
            "visible_text": (payload.get("visible_text") or "")[:1500],
            "inputs": payload.get("inputs") or [],
            "buttons": payload.get("buttons") or [],
            "forms": payload.get("forms") or [],
        },
        "extension": {
            "user_agent": payload.get("user_agent"),
            "capture_seconds": payload.get("capture_seconds"),
            "debugger_attached": payload.get("debugger_attached"),
            "hooks_injected": payload.get("hooks_injected"),
            "full_re": True,
        },
        "notes": notes,
        "auto_sign": payload.get("auto_sign") or {},
        "signing": payload.get("signing") or {},
    }
    # Full offline RE pipeline (hooks/crypto/graph/oracle meta)
    try:
        doc = enrich_extension_capture(doc, payload)
    except Exception as e:  # noqa: BLE001
        notes.append(f"enrich_extension_capture failed: {e}")
        doc["notes"] = notes
    return doc


def _count_by(entries: list[NetworkEntry], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in entries:
        k = getattr(e, field, None) or "other"
        out[str(k)] = out.get(str(k), 0) + 1
    return out


def _count_status(entries: list[NetworkEntry]) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in entries:
        k = str(e.status if e.status is not None else "pending")
        out[k] = out.get(k, 0) + 1
    return out


def save_extension_capture(payload: dict[str, Any]) -> dict[str, Any]:
    doc = build_capture_from_extension(payload)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    art = artifacts_dir() / "capture"
    art.mkdir(parents=True, exist_ok=True)
    path = art / f"ext-capture-{stamp}.json"
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    # optional pack draft
    pack_info = None
    if payload.get("write_pack"):
        try:
            from easy_rev.platforms.web.re.draft_protocol import write_protocol_pack

            host = urlparse(str(doc.get("url") or "site")).netloc or "ext-site"
            pack_id = payload.get("pack_id") or host.replace(".", "-").lower()
            pack_id = "".join(c if c.isalnum() or c in "-_." else "-" for c in pack_id)
            dest = Path(payload["pack_path"]) if payload.get("pack_path") else Path("packs") / pack_id
            pack_info = write_protocol_pack(
                pack_path=dest,
                pack_id=pack_id,
                capture_path=path,
                signup_url=doc.get("url"),
                apis=doc.get("apis") or [],
            )
        except Exception as e:  # noqa: BLE001
            pack_info = {"ok": False, "error": str(e)}

    auto = doc.get("auto_sign") or {}
    result = {
        "ok": True,
        "capture_path": str(path.resolve()),
        "url": doc.get("url"),
        "api_count": len(doc.get("apis") or []),
        "network_total": (doc.get("network_summary") or {}).get("total"),
        "top_apis": [
            {"method": a.get("method"), "url": a.get("url"), "score": a.get("score")}
            for a in (doc.get("apis") or [])[:8]
        ],
        "auto_sign": {
            "mode": auto.get("mode"),
            "best_signer": auto.get("best_signer"),
            "crypto_confidence": auto.get("crypto_confidence"),
            "signers_working": auto.get("signers_working"),
        },
        "capability": doc.get("capability"),
        "pack": pack_info,
        "next": [
            f'easy-rev ai call re.analyze -i \'{{"path":"{path}"}}\'',
            f'easy-rev ai call pack.from_capture -i \'{{"capture_path":"{path}"}}\'',
        ],
    }
    _STATE["last_capture_path"] = str(path.resolve())
    _STATE["last_result"] = result
    _STATE["count"] = int(_STATE.get("count") or 0) + 1
    return result


class _BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("bridge %s - %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        _cors_headers(self)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        _cors_headers(self)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/", "/health"}:
            self._send(
                200,
                {
                    "ok": True,
                    "service": "easy-rev-extension-bridge",
                    "port": _STATE.get("port"),
                    "count": _STATE.get("count"),
                    "last_capture_path": _STATE.get("last_capture_path"),
                    "auth_required": bool(_STATE.get("token")),
                },
            )
            return
        if path == "/last":
            self._send(200, {"ok": True, "result": _STATE.get("last_result")})
            return
        self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not _check_token(self):
            self._send(401, {"ok": False, "error": "invalid token"})
            return
        path = urlparse(self.path).path
        data = _read_json(self)
        if path in {"/capture", "/v1/capture"}:
            try:
                result = save_extension_capture(data)
                self._send(200, result)
            except Exception as e:  # noqa: BLE001
                logger.exception("extension capture failed")
                self._send(500, {"ok": False, "error": str(e)})
            return
        if path in {"/analyze", "/v1/analyze"}:
            # offline re-analyze last or given path
            try:
                import asyncio

                from easy_rev.platforms.web.re.capture_flow import analyze_capture_file

                p = data.get("path") or _STATE.get("last_capture_path")
                if not p:
                    self._send(400, {"ok": False, "error": "no capture path"})
                    return
                out = asyncio.run(analyze_capture_file(p))
                self._send(200, {"ok": True, "result": out})
            except Exception as e:  # noqa: BLE001
                self._send(500, {"ok": False, "error": str(e)})
            return
        self._send(404, {"ok": False, "error": "not found"})


def start_bridge(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    token: str | None = None,
    blocking: bool = False,
) -> dict[str, Any]:
    """Start localhost bridge. Returns connection info for the extension."""
    if _STATE.get("server") is not None:
        return {
            "ok": True,
            "already_running": True,
            "host": host,
            "port": _STATE.get("port") or port,
            "url": f"http://{host}:{_STATE.get('port') or port}",
            "token": _STATE.get("token"),
        }

    server = ThreadingHTTPServer((host, port), _BridgeHandler)
    _STATE["server"] = server
    _STATE["port"] = server.server_address[1]
    _STATE["token"] = token
    _STATE["started_at"] = time.time()

    def _serve() -> None:
        logger.info("extension bridge listening on http://%s:%s", host, _STATE["port"])
        server.serve_forever()

    if blocking:
        _serve()
        return {"ok": True, "host": host, "port": _STATE["port"]}

    t = threading.Thread(target=_serve, name="easy-rev-ext-bridge", daemon=True)
    t.start()
    _STATE["thread"] = t
    return {
        "ok": True,
        "host": host,
        "port": _STATE["port"],
        "url": f"http://{host}:{_STATE['port']}",
        "token": token,
        "extension_dir": str(
            # .../src/easy_rev/platforms/web/re → repo root = parents[5]
            Path(__file__).resolve().parents[5] / "extensions" / "easy-rev-chrome"
        ),
        "health": f"http://{host}:{_STATE['port']}/health",
        "hint": "Load unpacked extension from extensions/easy-rev-chrome, then click Analyze",
    }


def stop_bridge() -> dict[str, Any]:
    server = _STATE.get("server")
    if not server:
        return {"ok": True, "stopped": False, "reason": "not_running"}
    try:
        server.shutdown()
    except Exception:  # noqa: BLE001
        pass
    try:
        server.server_close()
    except Exception:  # noqa: BLE001
        pass
    _STATE["server"] = None
    _STATE["thread"] = None
    return {"ok": True, "stopped": True}


def bridge_status() -> dict[str, Any]:
    return {
        "running": _STATE.get("server") is not None,
        "port": _STATE.get("port"),
        "url": (
            f"http://{DEFAULT_HOST}:{_STATE['port']}" if _STATE.get("port") else None
        ),
        "count": _STATE.get("count"),
        "last_capture_path": _STATE.get("last_capture_path"),
        "auth_required": bool(_STATE.get("token")),
    }
