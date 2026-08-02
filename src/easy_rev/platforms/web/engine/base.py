from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from easy_rev.core.types import BrowserProfile


class BrowserSession(ABC):
    page: Any

    @abstractmethod
    async def close(self) -> None: ...


class BrowserEngine(ABC):
    name: str

    @abstractmethod
    async def launch_session(self, profile: BrowserProfile) -> BrowserSession: ...

    @asynccontextmanager
    async def session(self, profile: BrowserProfile) -> AsyncIterator[BrowserSession]:
        s = await self.launch_session(profile)
        try:
            yield s
        finally:
            await s.close()


def resolve_engine(
    name: str = "auto",
    *,
    cdp_url: str | None = None,
    cdp_target_url: str | None = None,
    cdp_target_index: int | None = None,
    cdp_new_page_url: str | None = None,
) -> BrowserEngine:
    # CDP attach wins when URL provided or engine name is cdp/chrome/user
    if name in {"cdp", "chrome", "user", "user-chrome", "attach"} or cdp_url:
        from easy_rev.platforms.web.engine.cdp_engine import CdpEngine, normalize_cdp_url

        return CdpEngine(
            cdp_url=normalize_cdp_url(cdp_url or "http://127.0.0.1:9222"),
            target_url=cdp_target_url,
            target_index=cdp_target_index,
            new_page_url=cdp_new_page_url,
        )
    if name in {"http", "protocol", "none"}:
        from easy_rev.platforms.web.engine.protocol_engine import ProtocolBrowserEngine

        return ProtocolBrowserEngine()
    if name == "mock":
        from easy_rev.platforms.web.engine.mock import MockEngine

        return MockEngine()
    if name == "camoufox":
        from easy_rev.platforms.web.engine.camoufox_engine import CamoufoxEngine

        return CamoufoxEngine()
    if name == "auto":
        try:
            from easy_rev.config import get_settings

            preferred = get_settings().engine
            if preferred in {"camoufox", "mock", "http", "protocol", "cdp", "chrome"}:
                return resolve_engine(preferred, cdp_url=cdp_url)
        except Exception:  # noqa: BLE001
            pass
        try:
            from easy_rev.platforms.web.engine.camoufox_engine import CamoufoxEngine

            return CamoufoxEngine()
        except Exception:  # noqa: BLE001
            from easy_rev.platforms.web.engine.mock import MockEngine

            return MockEngine()
    raise ValueError(f"unknown engine: {name}")


def resolve_engine_from_args(args: dict | None = None) -> BrowserEngine:
    """Shared helper for AI tools: engine + optional cdp_* fields."""
    args = args or {}
    cdp = args.get("cdp_url") or args.get("cdp") or args.get("chrome_cdp")
    eng = args.get("engine") or ("cdp" if cdp else "auto")
    return resolve_engine(
        str(eng),
        cdp_url=str(cdp) if cdp else None,
        cdp_target_url=args.get("cdp_target_url") or args.get("tab_url") or args.get("target_url"),
        cdp_target_index=args.get("cdp_target_index")
        if args.get("cdp_target_index") is not None
        else args.get("tab_index"),
        cdp_new_page_url=args.get("cdp_new_page_url") or args.get("new_tab_url"),
    )
