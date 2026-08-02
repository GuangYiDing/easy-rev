"""Attach to a user-owned browser via Chrome DevTools Protocol (CDP).

Typical flow:
  1. User starts Chrome with remote debugging, e.g.
     /Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome \\
       --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug
  2. easy-rev connects: engine=cdp, cdp_url=http://127.0.0.1:9222
  3. We never close the user's browser — only disconnect Playwright.
"""

from __future__ import annotations

import logging
from typing import Any

from easy_rev.core.types import BrowserProfile
from easy_rev.platforms.web.engine.base import BrowserEngine, BrowserSession

logger = logging.getLogger(__name__)


class CdpSession(BrowserSession):
    """Session bound to an existing browser tab. close() disconnects only."""

    def __init__(
        self,
        *,
        playwright: Any,
        browser: Any,
        context: Any,
        page: Any,
        owned_page: bool = False,
    ) -> None:
        self._pw = playwright
        self._browser = browser
        self._context = context
        self.page = page
        self._owned_page = owned_page  # if we created a new tab ourselves
        self._closed = False

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Never browser.close() — that would kill the user's Chrome.
        try:
            if self._owned_page and self.page is not None:
                try:
                    await self.page.close()
                except Exception:  # noqa: BLE001
                    pass
        finally:
            try:
                if self._browser is not None:
                    await self._browser.close()  # disconnect CDP, not kill Chrome
            except Exception:  # noqa: BLE001
                logger.debug("cdp browser disconnect failed", exc_info=True)
            try:
                if self._pw is not None:
                    await self._pw.stop()
            except Exception:  # noqa: BLE001
                pass


class CdpEngine(BrowserEngine):
    """Connect to Chrome/Edge/Chromium over CDP."""

    name = "cdp"

    def __init__(
        self,
        *,
        cdp_url: str = "http://127.0.0.1:9222",
        target_url: str | None = None,
        target_index: int | None = None,
        new_page_url: str | None = None,
    ) -> None:
        self.cdp_url = cdp_url.rstrip("/")
        self.target_url = target_url
        self.target_index = target_index
        self.new_page_url = new_page_url

    async def launch_session(self, profile: BrowserProfile) -> BrowserSession:
        try:
            from playwright.async_api import async_playwright
        except ImportError as e:
            raise ImportError(
                "playwright is required for CDP attach. "
                "Install: pip install playwright && playwright install chromium "
                "(or use the playwright that comes with camoufox)."
            ) from e

        # Profile may carry cdp overrides
        cdp_url = getattr(profile, "cdp_url", None) or self.cdp_url
        target_url = getattr(profile, "cdp_target_url", None) or self.target_url
        target_index = getattr(profile, "cdp_target_index", None)
        if target_index is None:
            target_index = self.target_index
        new_page_url = getattr(profile, "cdp_new_page_url", None) or self.new_page_url

        pw = await async_playwright().start()
        try:
            browser = await pw.chromium.connect_over_cdp(cdp_url)
        except Exception as e:
            await pw.stop()
            raise ConnectionError(
                f"CDP connect failed ({cdp_url}): {e}. "
                "Start Chrome with --remote-debugging-port=9222 "
                "(see docs/reverse-engineering.md#user-chrome)."
            ) from e

        # Prefer default context (user's existing windows)
        contexts = browser.contexts
        if not contexts:
            # Rare: create a context (still same browser)
            context = await browser.new_context()
        else:
            context = contexts[0]
            # If multiple contexts, prefer one that has matching pages
            if target_url:
                for ctx in contexts:
                    for p in ctx.pages:
                        if target_url in (p.url or ""):
                            context = ctx
                            break

        page, owned = await _pick_page(
            context,
            target_url=target_url,
            target_index=target_index,
            new_page_url=new_page_url,
        )
        logger.info(
            "CDP attached cdp=%s page=%s owned_tab=%s",
            cdp_url,
            getattr(page, "url", None),
            owned,
        )
        return CdpSession(
            playwright=pw,
            browser=browser,
            context=context,
            page=page,
            owned_page=owned,
        )


async def _pick_page(
    context: Any,
    *,
    target_url: str | None,
    target_index: int | None,
    new_page_url: str | None,
) -> tuple[Any, bool]:
    pages = list(context.pages or [])
    if target_url:
        # Prefer exact-ish match, then includes
        for p in pages:
            if (p.url or "") == target_url:
                return p, False
        for p in pages:
            if target_url in (p.url or ""):
                return p, False
    if target_index is not None and 0 <= target_index < len(pages):
        return pages[target_index], False
    if pages and not new_page_url:
        # default: last non-blank focused-ish page
        for p in reversed(pages):
            u = p.url or ""
            if u and not u.startswith("chrome://") and not u.startswith("about:"):
                return p, False
        return pages[-1], False

    # Create a new tab in the user's browser
    page = await context.new_page()
    if new_page_url:
        await page.goto(new_page_url, wait_until="domcontentloaded")
    return page, True


async def list_cdp_targets(cdp_url: str = "http://127.0.0.1:9222") -> dict[str, Any]:
    """List open pages/tabs on a remote-debugging Chrome (no full attach needed for HTTP)."""
    import httpx

    base = cdp_url.rstrip("/")
    # Chrome exposes /json/list
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{base}/json/list")
            r.raise_for_status()
            targets = r.json()
        except Exception as e:  # noqa: BLE001
            # fallback version endpoint for diagnostics
            ver = None
            try:
                vr = await client.get(f"{base}/json/version")
                ver = vr.json()
            except Exception:  # noqa: BLE001
                pass
            return {
                "ok": False,
                "cdp_url": base,
                "error": str(e),
                "version": ver,
                "hint": (
                    "Launch Chrome with remote debugging, e.g.\n"
                    "  macOS: open -a 'Google Chrome' --args "
                    "--remote-debugging-port=9222 "
                    "--user-data-dir=$HOME/chrome-easy-rev-debug\n"
                    "  Then: easy-rev re browser-list"
                ),
            }

    tabs = []
    for t in targets if isinstance(targets, list) else []:
        if not isinstance(t, dict):
            continue
        typ = t.get("type") or ""
        if typ not in {"page", "webview", ""}:
            # still include pages primarily
            if typ != "page":
                continue
        tabs.append(
            {
                "id": t.get("id"),
                "title": t.get("title"),
                "url": t.get("url"),
                "type": typ or "page",
                "webSocketDebuggerUrl": t.get("webSocketDebuggerUrl"),
                "faviconUrl": t.get("faviconUrl"),
            }
        )
    version = None
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            vr = await client.get(f"{base}/json/version")
            version = vr.json()
    except Exception:  # noqa: BLE001
        pass

    return {
        "ok": True,
        "cdp_url": base,
        "browser": (version or {}).get("Browser"),
        "user_agent": (version or {}).get("User-Agent"),
        "tabs": tabs,
        "count": len(tabs),
    }


def normalize_cdp_url(url: str | None) -> str:
    if not url:
        return "http://127.0.0.1:9222"
    u = url.strip().rstrip("/")
    if u.isdigit():
        return f"http://127.0.0.1:{u}"
    if u.startswith(":"):
        return f"http://127.0.0.1{u}"
    if "://" not in u:
        return f"http://{u}"
    return u
