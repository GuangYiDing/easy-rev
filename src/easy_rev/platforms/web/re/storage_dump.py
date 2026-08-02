"""Dump cookies + WebStorage for reverse-engineering sessions."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

STORAGE_JS = r"""() => {
  const ls = {};
  const ss = {};
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k == null) continue;
      let v = localStorage.getItem(k) || '';
      if (v.length > 2000) v = v.slice(0, 2000) + '…';
      ls[k] = v;
    }
  } catch (e) {}
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k == null) continue;
      let v = sessionStorage.getItem(k) || '';
      if (v.length > 2000) v = v.slice(0, 2000) + '…';
      ss[k] = v;
    }
  } catch (e) {}
  return {
    localStorage: ls,
    sessionStorage: ss,
    origin: location.origin,
    href: location.href,
  };
}"""


async def dump_browser_storage(page: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "cookies": [],
        "localStorage": {},
        "sessionStorage": {},
        "url": getattr(page, "url", None),
    }
    try:
        context = getattr(page, "context", None)
        if context is not None and hasattr(context, "cookies"):
            out["cookies"] = await context.cookies()
        elif hasattr(page, "cookies"):
            out["cookies"] = await page.cookies()
    except Exception as e:  # noqa: BLE001
        out["cookies_error"] = str(e)

    try:
        if hasattr(page, "evaluate"):
            data = await page.evaluate(STORAGE_JS)
            if isinstance(data, dict):
                out["localStorage"] = data.get("localStorage") or {}
                out["sessionStorage"] = data.get("sessionStorage") or {}
                out["origin"] = data.get("origin")
                out["url"] = data.get("href") or out["url"]
    except Exception as e:  # noqa: BLE001
        out["storage_error"] = str(e)

    # Compact cookie view for agents
    compact = []
    for c in out.get("cookies") or []:
        if not isinstance(c, dict):
            continue
        compact.append(
            {
                "name": c.get("name"),
                "value": _preview(str(c.get("value") or ""), 120),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "httpOnly": c.get("httpOnly"),
                "secure": c.get("secure"),
            }
        )
    out["cookies_compact"] = compact
    return out


def _preview(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + "…"


def cookies_to_header(cookies: list[dict[str, Any]]) -> str:
    parts = []
    for c in cookies:
        name = c.get("name")
        value = c.get("value")
        if name is not None and value is not None:
            parts.append(f"{name}={value}")
    return "; ".join(parts)
