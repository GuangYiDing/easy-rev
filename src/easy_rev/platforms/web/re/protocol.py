"""Helpers for pure protocol (HTTP-only) packs — no browser engine."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# Actions that never require a browser page
NO_BROWSER_ACTIONS = frozenset(
    {
        "http.request",
        "wait",
        "set_var",
        "log",
        "noop",
        "dry_success",
        "account.update",
        "email.wait",
        "sms.acquire",
        "sms.wait",
        # assert / extract: partially supported without page (see runtime)
        "assert",
        "extract",
        "captcha",  # captcha solvers often need page for sitekey auto-detect; optional
    }
)

# Actions that definitely need a live page
BROWSER_REQUIRED_ACTIONS = frozenset(
    {
        "goto",
        "click",
        "click_when_enabled",
        "click_first_visible",
        "fill",
        "fill_form",
        "type",
        "select",
        "press",
        "hover",
        "check",
        "uncheck",
        "wait_for",
        "wait_enabled",
        "wait_url",
        "screenshot",
        "save_session",
        "eval",
        "http.from_browser",  # hybrid: needs live page unless optional
        "http.sign_via_browser",  # strong signature oracle
    }
)

PROTOCOL_ENGINES = frozenset({"http", "protocol", "none"})


def is_protocol_engine(name: str | None) -> bool:
    return (name or "").lower() in PROTOCOL_ENGINES


def flow_needs_browser(steps: Iterable[Any]) -> bool:
    """Return True if any step requires a Playwright page."""
    for step in steps:
        action = getattr(step, "action", None)
        if action is None and isinstance(step, dict):
            action = step.get("action")
        if not action:
            continue
        act = str(action)
        if act == "http.from_browser":
            params = step.params() if hasattr(step, "params") else (step if isinstance(step, dict) else {})
            # optional import is skipped without page — pure protocol OK
            if (params or {}).get("required"):
                return True
            # still prefer browser if present in hybrid packs; don't force for engine=http
            continue
        if act in BROWSER_REQUIRED_ACTIONS:
            return True
        if act == "extract":
            params = step.params() if hasattr(step, "params") else (step if isinstance(step, dict) else {})
            source = (params or {}).get("source", "html")
            if source in {"html", "page", None, ""}:
                # default extract from HTML needs page
                if (params or {}).get("from_extract") or (params or {}).get("json_path"):
                    continue
                return True
        if act == "assert":
            params = step.params() if hasattr(step, "params") else (step if isinstance(step, dict) else {})
            if _assert_needs_page(params or {}):
                return True
        if act == "captcha":
            # captcha without explicit site_key often scrapes DOM
            params = step.params() if hasattr(step, "params") else (step if isinstance(step, dict) else {})
            if not (params or {}).get("site_key") and not (params or {}).get("token"):
                return True
    return False


def _assert_needs_page(params: dict[str, Any]) -> bool:
    conds = list(params.get("any") or []) + list(params.get("all") or [])
    if not conds:
        return True
    page_keys = {
        "url_includes",
        "url_equals",
        "selector_exists",
        "text_includes",
    }
    non_page_keys = {
        "extract_exists",
        "extract_equals",
        "extract_includes",
        "var_equals",
        "http_status",
        "meta_equals",
    }
    for c in conds:
        if not isinstance(c, dict):
            return True
        keys = set(c.keys())
        if keys & page_keys:
            return True
        if not (keys & non_page_keys):
            # unknown condition → assume may need page
            if not keys:
                return True
    return False


def pack_prefers_protocol(pack: Any) -> bool:
    """True if pack.yaml requires.engine is http/protocol/none."""
    try:
        eng = (pack.manifest.requires.engine or "").lower()
        return is_protocol_engine(eng)
    except Exception:  # noqa: BLE001
        return False


class NullPage:
    """Placeholder page object for protocol-only runs (fails clearly if misused)."""

    url = "about:protocol"

    async def goto(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("protocol engine has no browser page (goto not available)")

    async def click(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("protocol engine has no browser page")

    async def fill(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("protocol engine has no browser page")

    async def content(self) -> str:
        return ""

    async def screenshot(self, *args: Any, **kwargs: Any) -> bytes:
        return b""

    async def evaluate(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("protocol engine has no browser page")

    async def wait_for_selector(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("protocol engine has no browser page")

    async def close(self) -> None:
        return None


class ProtocolSession:
    page: Any

    def __init__(self) -> None:
        self.page = NullPage()

    async def close(self) -> None:
        return None


class ProtocolEngine:
    """No-op browser engine for pure HTTP packs."""

    name = "http"

    async def launch_session(self, profile: Any) -> ProtocolSession:
        return ProtocolSession()
