"""Build BrowserProfile for CDP attach from tool args."""

from __future__ import annotations

from typing import Any

from easy_rev.core.types import BrowserProfile
from easy_rev.platforms.web.engine.cdp_engine import normalize_cdp_url


def profile_from_args(args: dict[str, Any] | None = None) -> BrowserProfile:
    args = args or {}
    cdp = args.get("cdp_url") or args.get("cdp") or args.get("chrome_cdp")
    headless = bool(args.get("headless", True))
    # CDP ignores headless (uses user's window); keep field for type compatibility
    return BrowserProfile(
        headless=headless,
        cdp_url=normalize_cdp_url(str(cdp)) if cdp else None,
        cdp_target_url=args.get("cdp_target_url")
        or args.get("tab_url")
        or args.get("target_url"),
        cdp_target_index=(
            int(args["cdp_target_index"])
            if args.get("cdp_target_index") is not None
            else (int(args["tab_index"]) if args.get("tab_index") is not None else None)
        ),
        cdp_new_page_url=args.get("cdp_new_page_url") or args.get("new_tab_url"),
    )


def uses_cdp(args: dict[str, Any] | None = None) -> bool:
    args = args or {}
    eng = str(args.get("engine") or "").lower()
    return bool(
        args.get("cdp_url")
        or args.get("cdp")
        or args.get("chrome_cdp")
        or eng in {"cdp", "chrome", "user", "user-chrome", "attach"}
    )
