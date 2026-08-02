"""Bridge browser session state → protocol HttpClient (cookies, UA, storage tokens)."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

UA_JS = "() => navigator.userAgent || ''"
STORAGE_TOKEN_JS = r"""() => {
  const out = {};
  const pick = (store, prefix) => {
    try {
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        if (!k) continue;
        const kl = k.toLowerCase();
        if (
          kl.includes('token') || kl.includes('csrf') || kl.includes('xsrf') ||
          kl.includes('auth') || kl.includes('session') || kl.includes('jwt')
        ) {
          let v = store.getItem(k) || '';
          if (v.length > 2000) v = v.slice(0, 2000);
          out[prefix + k] = v;
        }
      }
    } catch (e) {}
  };
  pick(localStorage, 'ls:');
  pick(sessionStorage, 'ss:');
  return out;
}"""


async def get_user_agent(page: Any) -> str | None:
    if not page or not hasattr(page, "evaluate"):
        return None
    try:
        ua = await page.evaluate(UA_JS)
        return str(ua) if ua else None
    except Exception as e:  # noqa: BLE001
        logger.debug("get_user_agent failed: %s", e)
        return None


async def get_browser_cookies(page: Any) -> list[dict[str, Any]]:
    """Return Playwright-style cookie dicts."""
    if not page:
        return []
    try:
        context = getattr(page, "context", None)
        if context is not None and hasattr(context, "cookies"):
            return list(await context.cookies())
        if hasattr(page, "cookies"):
            return list(await page.cookies())
    except Exception as e:  # noqa: BLE001
        logger.warning("get_browser_cookies failed: %s", e)
    return []


async def get_storage_tokens(page: Any) -> dict[str, str]:
    if not page or not hasattr(page, "evaluate"):
        return {}
    try:
        data = await page.evaluate(STORAGE_TOKEN_JS)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception as e:  # noqa: BLE001
        logger.debug("storage tokens failed: %s", e)
    return {}


def cookies_list_to_header(cookies: list[dict[str, Any]]) -> str:
    parts = []
    for c in cookies:
        n, v = c.get("name"), c.get("value")
        if n is not None and v is not None:
            parts.append(f"{n}={v}")
    return "; ".join(parts)


def cookies_list_to_map(cookies: list[dict[str, Any]]) -> dict[str, str]:
    return {
        str(c["name"]): str(c["value"])
        for c in cookies
        if c.get("name") is not None and c.get("value") is not None
    }


async def import_browser_into_http(
    page: Any,
    http: Any,
    *,
    include_storage_tokens: bool = True,
    set_user_agent: bool = True,
) -> dict[str, Any]:
    """Push browser cookies (+ optional UA / token storage) into HttpClient.

    Returns a summary for meta/artifacts.
    """
    cookies = await get_browser_cookies(page)
    summary: dict[str, Any] = {
        "cookies_imported": 0,
        "cookie_names": [],
        "user_agent": None,
        "storage_tokens": {},
    }

    # Prefer domain-aware set when possible
    for c in cookies:
        name = c.get("name")
        value = c.get("value")
        if name is None or value is None:
            continue
        domain = c.get("domain")
        try:
            if domain and hasattr(http, "set_cookie_full"):
                http.set_cookie_full(
                    str(name),
                    str(value),
                    domain=str(domain).lstrip("."),
                    path=str(c.get("path") or "/"),
                )
            elif domain:
                http.set_cookies({str(name): str(value)}, domain=str(domain).lstrip("."))
            else:
                http.set_cookies({str(name): str(value)})
            summary["cookies_imported"] += 1
            summary["cookie_names"].append(str(name))
        except Exception as e:  # noqa: BLE001
            logger.debug("set cookie %s failed: %s", name, e)

    if set_user_agent:
        ua = await get_user_agent(page)
        if ua and hasattr(http, "set_default_header"):
            http.set_default_header("User-Agent", ua)
            summary["user_agent"] = ua[:120]

    if include_storage_tokens:
        tokens = await get_storage_tokens(page)
        summary["storage_tokens"] = {
            k: (v[:80] + "…" if len(v) > 80 else v) for k, v in tokens.items()
        }
        # Common CSRF header injection if we find a short token
        for k, v in tokens.items():
            kl = k.lower()
            if any(x in kl for x in ("csrf", "xsrf")) and 8 <= len(v) <= 512:
                if hasattr(http, "set_default_header"):
                    http.set_default_header("X-CSRF-Token", v)
                    http.set_default_header("X-XSRF-Token", v)
                break

    return summary


def origin_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        p = urlparse(url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    except Exception:  # noqa: BLE001
        return None
    return None
