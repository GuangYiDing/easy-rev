from __future__ import annotations

from typing import Any

from easy_rev.core.types import BrowserProfile
from easy_rev.platforms.web.engine.base import BrowserEngine, BrowserSession


class MockKeyboard:
    async def press(self, key: str) -> None:
        return None


class MockPage:
    def __init__(self) -> None:
        self._url = "about:blank"
        self._html = "<html><body><div class='success'>ok</div></body></html>"
        self.keyboard = MockKeyboard()
        self.context = MockContext()
        self._listeners: dict[str, list[Any]] = {}

    @property
    def url(self) -> str:
        return self._url

    def on(self, event: str, handler: Any) -> None:
        """No-op network events for NetworkCapture attach in tests."""
        self._listeners.setdefault(event, []).append(handler)

    async def goto(self, url: str, **kwargs: Any) -> None:
        self._url = url
        self._html = (
            f"<html><body data-url='{url}'>"
            f"<form><input name='email'/><input name='password'/>"
            f"<button type='submit'>Go</button></form>"
            f"<div class='success'>ok</div></body></html>"
        )

    async def click(self, selector: str, **kwargs: Any) -> None:
        return None

    async def fill(self, selector: str, value: str, **kwargs: Any) -> None:
        return None

    async def type(self, selector: str, text: str, **kwargs: Any) -> None:
        return None

    async def press(self, selector: str, key: str, **kwargs: Any) -> None:
        return None

    async def hover(self, selector: str, **kwargs: Any) -> None:
        return None

    async def check(self, selector: str, **kwargs: Any) -> None:
        return None

    async def uncheck(self, selector: str, **kwargs: Any) -> None:
        return None

    async def select_option(self, selector: str, **kwargs: Any) -> None:
        return None

    async def wait_for_selector(self, selector: str, **kwargs: Any) -> None:
        return None

    async def content(self) -> str:
        return self._html

    async def screenshot(self, **kwargs: Any) -> bytes:
        path = kwargs.get("path")
        if path:
            with open(path, "wb") as f:
                f.write(b"")
        return b""

    async def evaluate(self, expression: str, arg: Any = None) -> Any:
        return None

    async def close(self) -> None:
        return None


class MockContext:
    async def cookies(self) -> list[dict[str, Any]]:
        return [{"name": "mock", "value": "1", "domain": "example.com", "path": "/"}]

    async def storage_state(self) -> dict[str, Any]:
        return {"cookies": await self.cookies(), "origins": []}


class MockSession(BrowserSession):
    def __init__(self) -> None:
        self.page = MockPage()
        self._browser = self  # allow pool recycle path
        self.launch_count = 1

    async def new_page(self) -> MockPage:
        self.page = MockPage()
        return self.page

    async def recycle(self) -> None:
        self.page = MockPage()
        self.launch_count += 1

    async def close(self) -> None:
        return None


class MockEngine(BrowserEngine):
    name = "mock"

    def __init__(self) -> None:
        self.launch_calls = 0

    async def launch_session(self, profile: BrowserProfile) -> BrowserSession:
        self.launch_calls += 1
        return MockSession()
