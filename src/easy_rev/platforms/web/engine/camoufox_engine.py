from __future__ import annotations

import logging
from typing import Any

from easy_rev.core.types import BrowserProfile
from easy_rev.platforms.web.engine.base import BrowserEngine, BrowserSession

logger = logging.getLogger(__name__)


class CamoufoxSession(BrowserSession):
    def __init__(self, browser: Any, page: Any, cm: Any) -> None:
        self._browser = browser
        self._cm = cm
        self.page = page

    async def recycle(self) -> None:
        """New page + clear cookies for next account without relaunching Camoufox."""
        old = self.page
        context = getattr(old, "context", None) if old is not None else None
        if old is not None:
            try:
                await old.close()
            except Exception:  # noqa: BLE001
                pass
        if context is not None:
            try:
                if hasattr(context, "clear_cookies"):
                    await context.clear_cookies()
            except Exception:  # noqa: BLE001
                pass
        self.page = await self._browser.new_page()

    async def close(self) -> None:
        try:
            try:
                await self.page.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                await self._browser.close()
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                await self._cm.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                logger.exception("failed closing camoufox context manager")


class CamoufoxEngine(BrowserEngine):
    """Camoufox engine — official Python AsyncCamoufox API."""

    name = "camoufox"

    def __init__(self) -> None:
        try:
            from camoufox.async_api import AsyncCamoufox  # type: ignore[import-untyped]
        except ImportError as e:
            raise ImportError(
                "camoufox is not installed. Run: pip install 'easy-rev[camoufox]' "
                "&& python -m camoufox fetch"
            ) from e
        self._async_camoufox = AsyncCamoufox

    async def launch_session(self, profile: BrowserProfile) -> BrowserSession:
        launch_kwargs: dict[str, Any] = {
            "headless": profile.headless,
            "locale": profile.locale,
            "humanize": profile.humanize,
        }
        if profile.timezone_id:
            # camoufox accepts timezone / timezone_id depending on version
            launch_kwargs["timezone"] = profile.timezone_id

        if profile.proxy:
            proxy: dict[str, str] = {"server": profile.proxy.server}
            if profile.proxy.username:
                proxy["username"] = profile.proxy.username
            if profile.proxy.password:
                proxy["password"] = profile.proxy.password
            launch_kwargs["proxy"] = proxy
            if profile.geoip:
                launch_kwargs["geoip"] = True

        cm = self._async_camoufox(**launch_kwargs)
        try:
            browser = await cm.__aenter__()
        except Exception as e:  # noqa: BLE001
            # Camoufox geoip probes public IP via the proxy; flaky residential
            # peers raise InvalidIP / Connection reset and abort launch entirely.
            # Fall back to proxy-without-geoip so registration can still proceed.
            msg = str(e).lower()
            geoip_on = bool(launch_kwargs.get("geoip"))
            looks_geoip = any(
                k in msg
                for k in (
                    "invalidip",
                    "failed to get ip",
                    "geoip",
                    "connection reset",
                    "connection aborted",
                )
            )
            if geoip_on and looks_geoip:
                logger.warning(
                    "camoufox geoip failed (%s); retrying launch without geoip", e
                )
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass
                launch_kwargs = {k: v for k, v in launch_kwargs.items() if k != "geoip"}
                cm = self._async_camoufox(**launch_kwargs)
                browser = await cm.__aenter__()
            else:
                raise
        page = await browser.new_page()
        return CamoufoxSession(browser, page, cm)
