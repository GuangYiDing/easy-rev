"""W3C HAR 1.2 export (compatible with Chrome/Charles/HAR viewers)."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from easy_rev.platforms.web.re.network import NetworkCapture, NetworkEntry


def _headers_list(headers: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": str(k), "value": str(v)} for k, v in headers.items()]


def _query_string(url: str) -> list[dict[str, str]]:
    try:
        q = urlsplit(url).query
        return [{"name": k, "value": v} for k, v in parse_qsl(q, keep_blank_values=True)]
    except Exception:  # noqa: BLE001
        return []


def _post_data(entry: NetworkEntry) -> dict[str, Any] | None:
    if not entry.post_data:
        return None
    mime = ""
    for k, v in entry.request_headers.items():
        if k.lower() == "content-type":
            mime = v
            break
    out: dict[str, Any] = {
        "mimeType": mime or "application/octet-stream",
        "text": entry.post_data,
    }
    if "json" in mime or (entry.post_data[:1] in "{["):
        out["mimeType"] = mime or "application/json"
    elif "www-form-urlencoded" in mime:
        try:
            out["params"] = [
                {"name": k, "value": v}
                for k, v in parse_qsl(entry.post_data, keep_blank_values=True)
            ]
        except Exception:  # noqa: BLE001
            pass
    return out


def entry_to_har(entry: NetworkEntry) -> dict[str, Any]:
    started_iso = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(entry.started_at))
    status = int(entry.status or 0)
    body = entry.response_body or ""
    content: dict[str, Any] = {
        "size": entry.response_body_bytes or len(body.encode("utf-8", errors="replace")),
        "mimeType": entry.content_type or "application/octet-stream",
        "text": body,
    }
    if entry.response_body_truncated:
        content["comment"] = "truncated by easy-rev capture"

    return {
        "startedDateTime": started_iso,
        "time": float(entry.timing_ms or 0),
        "request": {
            "method": entry.method or "GET",
            "url": entry.url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _headers_list(entry.request_headers),
            "queryString": _query_string(entry.url),
            "headersSize": -1,
            "bodySize": len((entry.post_data or "").encode("utf-8", errors="replace")),
            "postData": _post_data(entry),
        },
        "response": {
            "status": status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _headers_list(entry.response_headers),
            "content": content,
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": content["size"],
        },
        "cache": {},
        "timings": {
            "blocked": -1,
            "dns": -1,
            "connect": -1,
            "send": 0,
            "wait": float(entry.timing_ms or 0),
            "receive": 0,
            "ssl": -1,
        },
        "serverIPAddress": "",
        "connection": "",
        "comment": "",
        "_resourceType": entry.resource_type,
        "_easyReg": {
            "score": entry.score,
            "tags": entry.tags,
            "api_summary": entry.api_summary,
            "failed": entry.failed,
        },
    }


def capture_to_har(
    capture: NetworkCapture,
    *,
    page_url: str | None = None,
    title: str = "easy-rev capture",
) -> dict[str, Any]:
    """Full HAR 1.2 document."""
    from easy_rev import __version__

    entries = [entry_to_har(e) for e in capture.entries]
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "easy-rev", "version": __version__},
            "browser": {"name": "camoufox/playwright", "version": ""},
            "pages": [
                {
                    "startedDateTime": time.strftime(
                        "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()
                    ),
                    "id": "page_1",
                    "title": title,
                    "pageTimings": {"onContentLoad": -1, "onLoad": -1},
                }
            ],
            "entries": entries,
            "comment": page_url or "",
        }
    }


def write_har_file(capture: NetworkCapture, path: str, **kwargs: Any) -> str:
    import json
    from pathlib import Path

    doc = capture_to_har(capture, **kwargs)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(p.resolve())
