"""Protocol-mode HTTP client (replay reverse-engineered APIs)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HttpResult:
    ok: bool
    status: int
    url: str
    headers: dict[str, str]
    text: str
    json_data: Any | None = None
    elapsed_ms: float = 0.0
    error: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)

    def to_dict(self, *, body_limit: int = 8000) -> dict[str, Any]:
        text = self.text
        truncated = False
        if len(text) > body_limit:
            text = text[:body_limit] + "…"
            truncated = True
        return {
            "ok": self.ok,
            "status": self.status,
            "url": self.url,
            "headers": self.headers,
            "text": text,
            "text_truncated": truncated,
            "json": self.json_data if not truncated else _truncate_json(self.json_data),
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "cookies": self.cookies,
        }


def _truncate_json(data: Any, limit: int = 4000) -> Any:
    if data is None:
        return None
    try:
        s = json.dumps(data, ensure_ascii=False)
        if len(s) <= limit:
            return data
        return json.loads(s[:limit] + ('"' if s[:limit].count('"') % 2 else ""))
    except Exception:  # noqa: BLE001
        return str(data)[:limit]


class HttpClient:
    """Shared cookie-jar HTTP client for AI tools and flow ``http.request`` steps.

    Backend:
      - ``httpx`` (default)
      - ``curl_cffi`` when ``impersonate`` is set (Chrome TLS fingerprint) if installed
    """

    def __init__(
        self,
        *,
        proxy: str | None = None,
        timeout_s: float = 30.0,
        user_agent: str | None = None,
        verify: bool = True,
        impersonate: str | None = None,
    ) -> None:
        self.timeout_s = timeout_s
        self.proxy = proxy
        self.verify = verify
        self.impersonate = impersonate
        self._default_headers: dict[str, str] = {}
        if user_agent:
            self._default_headers["User-Agent"] = user_agent
        self._backend = "httpx"
        self._client: Any = None
        self._curl: Any = None

        if impersonate:
            try:
                from curl_cffi.requests import AsyncSession  # type: ignore[import-untyped]

                self._curl = AsyncSession(
                    impersonate=impersonate,
                    timeout=timeout_s,
                    proxy=proxy,
                    verify=verify,
                    headers=dict(self._default_headers),
                )
                self._backend = "curl_cffi"
            except Exception as e:  # noqa: BLE001
                logger.info("curl_cffi unavailable (%s); falling back to httpx", e)

        if self._backend == "httpx":
            import httpx

            self._client = httpx.AsyncClient(
                timeout=timeout_s,
                follow_redirects=True,
                proxy=proxy,
                verify=verify,
                headers=dict(self._default_headers),
            )

    def set_default_header(self, name: str, value: str) -> None:
        self._default_headers[name] = value
        if self._client is not None:
            self._client.headers[name] = value
        if self._curl is not None:
            try:
                self._curl.headers[name] = value
            except Exception:  # noqa: BLE001
                pass

    def _cookie_dict(self) -> dict[str, str]:
        try:
            if self._backend == "curl_cffi" and self._curl is not None:
                # curl_cffi cookies may be a RequestsCookieJar-like
                jar = getattr(self._curl, "cookies", None)
                if jar is None:
                    return {}
                try:
                    return dict(jar)
                except Exception:  # noqa: BLE001
                    return {getattr(c, "name", str(c)): getattr(c, "value", "") for c in jar}
            if self._client is not None:
                return dict(self._client.cookies)
        except Exception:  # noqa: BLE001
            return {}
        return {}

    @property
    def cookies(self) -> dict[str, str]:
        return self._cookie_dict()

    @property
    def backend(self) -> str:
        return self._backend

    def set_cookies(self, cookies: dict[str, str], *, domain: str | None = None) -> None:
        for k, v in cookies.items():
            self.set_cookie_full(k, v, domain=domain)

    def set_cookie_full(
        self,
        name: str,
        value: str,
        *,
        domain: str | None = None,
        path: str = "/",
    ) -> None:
        if self._client is not None:
            if domain:
                self._client.cookies.set(name, value, domain=domain, path=path)
            else:
                self._client.cookies.set(name, value)
        if self._curl is not None:
            try:
                if domain:
                    self._curl.cookies.set(name, value, domain=domain, path=path)
                else:
                    self._curl.cookies.set(name, value)
            except Exception:  # noqa: BLE001
                try:
                    self._curl.cookies[name] = value
                except Exception:  # noqa: BLE001
                    pass

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
        if self._curl is not None:
            try:
                await self._curl.close()
            except Exception:  # noqa: BLE001
                pass

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        form: dict[str, Any] | None = None,
        body: str | bytes | None = None,
        timeout_s: float | None = None,
    ) -> HttpResult:
        import time

        t0 = time.monotonic()
        merged_headers = {**self._default_headers, **(headers or {})}

        if self._backend == "curl_cffi" and self._curl is not None:
            return await self._request_curl(
                method,
                url,
                headers=merged_headers,
                params=params,
                json_body=json_body,
                form=form,
                body=body,
                timeout_s=timeout_s,
                t0=t0,
            )

        import httpx

        try:
            kwargs: dict[str, Any] = {
                "method": method.upper(),
                "url": url,
                "headers": merged_headers,
                "params": params,
                "timeout": timeout_s or self.timeout_s,
            }
            if json_body is not None:
                kwargs["json"] = json_body
            elif form is not None:
                kwargs["data"] = form
            elif body is not None:
                kwargs["content"] = body

            resp = await self._client.request(**kwargs)
            text = resp.text
            parsed: Any | None = None
            ct = resp.headers.get("content-type", "")
            if "json" in ct or text.strip()[:1] in "{[":
                try:
                    parsed = resp.json()
                except Exception:  # noqa: BLE001
                    parsed = None
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            return HttpResult(
                ok=resp.is_success,
                status=resp.status_code,
                url=str(resp.url),
                headers={k: v for k, v in resp.headers.items()},
                text=text,
                json_data=parsed,
                elapsed_ms=elapsed,
                cookies=self._cookie_dict(),
            )
        except httpx.HTTPError as e:
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            return HttpResult(
                ok=False,
                status=0,
                url=url,
                headers={},
                text="",
                error=str(e),
                elapsed_ms=elapsed,
                cookies=self._cookie_dict(),
            )

    async def _request_curl(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, Any] | None,
        json_body: Any | None,
        form: dict[str, Any] | None,
        body: str | bytes | None,
        timeout_s: float | None,
        t0: float,
    ) -> HttpResult:
        import time

        try:
            kwargs: dict[str, Any] = {
                "method": method.upper(),
                "url": url,
                "headers": headers,
                "params": params,
                "timeout": timeout_s or self.timeout_s,
                "allow_redirects": True,
            }
            if json_body is not None:
                kwargs["json"] = json_body
            elif form is not None:
                kwargs["data"] = form
            elif body is not None:
                kwargs["data"] = body
            resp = await self._curl.request(**kwargs)
            text = resp.text if hasattr(resp, "text") else str(resp.content or b"", "utf-8", "replace")
            parsed: Any | None = None
            try:
                parsed = resp.json()
            except Exception:  # noqa: BLE001
                if text.strip()[:1] in "{[":
                    try:
                        parsed = json.loads(text)
                    except Exception:  # noqa: BLE001
                        parsed = None
            status = int(getattr(resp, "status_code", 0) or 0)
            hdrs = {}
            try:
                hdrs = {k: v for k, v in dict(resp.headers).items()}
            except Exception:  # noqa: BLE001
                pass
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            return HttpResult(
                ok=200 <= status < 400,
                status=status,
                url=str(getattr(resp, "url", url)),
                headers=hdrs,
                text=text,
                json_data=parsed,
                elapsed_ms=elapsed,
                cookies=self._cookie_dict(),
            )
        except Exception as e:  # noqa: BLE001
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            return HttpResult(
                ok=False,
                status=0,
                url=url,
                headers={},
                text="",
                error=str(e),
                elapsed_ms=elapsed,
                cookies=self._cookie_dict(),
            )


def simple_json_path(data: Any, path: str) -> Any:
    """Tiny JSON path: ``$.a.b``, ``a.b``, ``$.items.0.id`` (dot + int index)."""
    if not path or path in {"$", "."}:
        return data
    p = path.strip()
    if p.startswith("$."):
        p = p[2:]
    elif p.startswith("$"):
        p = p[1:].lstrip(".")
    cur: Any = data
    if not p:
        return cur
    for part in p.split("."):
        if cur is None:
            return None
        if part.isdigit():
            idx = int(part)
            if isinstance(cur, list) and 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def apply_extracts(
    result: HttpResult,
    extracts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Extract named values from HTTP result into a dict.

    Extract item shapes:
      - {name, json_path: "$.data.id"}
      - {name, regex: "(\\\\d{6})", group: 1}
      - {name, header: "x-request-id"}
      - {name, cookie: "session"}
    """
    out: dict[str, Any] = {}
    for ex in extracts:
        if not isinstance(ex, dict):
            continue
        name = ex.get("name")
        if not name:
            continue
        val: Any = None
        if ex.get("json_path") or ex.get("jsonpath"):
            path = str(ex.get("json_path") or ex.get("jsonpath"))
            data = result.json_data
            if data is None and result.text:
                try:
                    data = json.loads(result.text)
                except Exception:  # noqa: BLE001
                    data = None
            val = simple_json_path(data, path)
        elif ex.get("regex"):
            m = re.search(str(ex["regex"]), result.text or "", re.I | re.S)
            if m:
                group = int(ex.get("group") or 1)
                try:
                    val = m.group(group)
                except IndexError:
                    val = m.group(0)
        elif ex.get("header"):
            hn = str(ex["header"]).lower()
            for k, v in result.headers.items():
                if k.lower() == hn:
                    val = v
                    break
        elif ex.get("cookie"):
            val = result.cookies.get(str(ex["cookie"]))
        if val is not None:
            out[str(name)] = val
    return out
