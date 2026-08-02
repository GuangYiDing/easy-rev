"""HTTP/protocol-only engine — no real browser."""

from __future__ import annotations

from typing import Any

from easy_rev.core.types import BrowserProfile
from easy_rev.platforms.web.engine.base import BrowserEngine, BrowserSession
from easy_rev.platforms.web.re.protocol import NullPage


class _ProtocolBrowserSession(BrowserSession):
    def __init__(self) -> None:
        self.page: Any = NullPage()

    async def close(self) -> None:
        return None


class ProtocolBrowserEngine(BrowserEngine):
    """Launch a null page so pure ``http.request`` packs skip Camoufox."""

    name = "http"

    async def launch_session(self, profile: BrowserProfile) -> BrowserSession:
        return _ProtocolBrowserSession()
