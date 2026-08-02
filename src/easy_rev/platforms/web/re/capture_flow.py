"""High-level site capture orchestration used by AI tools."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from easy_rev.core.paths import artifacts_dir
from easy_rev.core.types import BrowserProfile
from easy_rev.platforms.web.engine.base import resolve_engine, resolve_engine_from_args
from easy_rev.platforms.web.identity.generator import generate_account
from easy_rev.platforms.web.re.cdp_profile import profile_from_args, uses_cdp
from easy_rev.platforms.web.re.classify import api_candidates_as_dicts, suggest_http_steps
from easy_rev.platforms.web.re.network import NetworkCapture
from easy_rev.platforms.web.re.scripts import (
    DEFAULT_SEARCH_PATTERNS,
    absolute_script_urls,
    download_scripts,
    dump_inline_scripts,
    list_page_scripts,
    search_scripts,
)
from easy_rev.platforms.web.re.storage_dump import dump_browser_storage

logger = logging.getLogger(__name__)


async def _run_inspect_actions(page: Any, actions: list[Any], notes: list[str]) -> None:
    for i, act in enumerate(actions or []):
        if not isinstance(act, dict):
            continue
        try:
            if act.get("click"):
                await page.click(str(act["click"]), timeout=int(act.get("timeout_ms") or 5000))
                notes.append(f"action[{i}] click {act['click']}")
            elif act.get("fill") is not None and act.get("selector"):
                val = str(act.get("value") if act.get("value") is not None else act.get("fill") or "")
                await page.fill(str(act["selector"]), val)
                notes.append(f"action[{i}] fill {act['selector']}")
            elif act.get("type") is not None and act.get("selector"):
                val = str(act.get("value") if act.get("value") is not None else act.get("type") or "")
                if hasattr(page, "type"):
                    await page.type(str(act["selector"]), val)
                else:
                    await page.fill(str(act["selector"]), val)
                notes.append(f"action[{i}] type {act['selector']}")
            elif act.get("press") and act.get("selector"):
                await page.press(str(act["selector"]), str(act["press"]))
                notes.append(f"action[{i}] press {act['press']}")
            elif act.get("wait_for"):
                await page.wait_for_selector(
                    str(act["wait_for"]), timeout=int(act.get("timeout_ms") or 10000)
                )
                notes.append(f"action[{i}] wait_for {act['wait_for']}")
            elif act.get("eval") or act.get("evaluate"):
                expr = act.get("eval") or act.get("evaluate")
                await page.evaluate(str(expr))
                notes.append(f"action[{i}] eval")
            if act.get("wait_ms"):
                await asyncio.sleep(int(act["wait_ms"]) / 1000)
            else:
                await asyncio.sleep(0.35)
        except Exception as e:  # noqa: BLE001
            notes.append(f"action[{i}] failed: {e}")


async def _auto_fill_account(page: Any, account: Any, notes: list[str]) -> int:
    """Heuristic fill of common registration fields using generated account."""
    filled = 0
    mapping = [
        (
            "input[type=email], input[name*=email i], input[autocomplete=email], "
            "input[id*=email i], input[placeholder*=email i]",
            account.email,
        ),
        (
            "input[type=password], input[name*=pass i], input[autocomplete=new-password], "
            "input[autocomplete=current-password]",
            account.password,
        ),
        (
            "input[name*=user i], input[autocomplete=username], input[id*=username i], "
            "input[name=login]",
            account.username,
        ),
        (
            "input[name*=first i], input[id*=first i], input[autocomplete=given-name], "
            "#given-name",
            account.first_name,
        ),
        (
            "input[name*=last i], input[id*=last i], input[autocomplete=family-name], "
            "#family-name",
            account.last_name,
        ),
        (
            "input[type=tel], input[name*=phone i], input[autocomplete=tel], "
            "input[id*=phone i], input[name*=mobile i]",
            account.phone or "",
        ),
    ]
    for selector, value in mapping:
        if not value:
            continue
        try:
            # Prefer first visible match via evaluate + fill selector when possible
            loc = page.locator(selector) if hasattr(page, "locator") else None
            if loc is not None:
                count = await loc.count()
                for idx in range(min(count, 3)):
                    target = loc.nth(idx)
                    try:
                        if hasattr(target, "is_visible") and not await target.is_visible():
                            continue
                        await target.fill(str(value))
                        filled += 1
                        notes.append(f"auto_fill {selector[:48]}…")
                        break
                    except Exception:  # noqa: BLE001
                        continue
            else:
                await page.fill(selector, str(value))
                filled += 1
                notes.append(f"auto_fill {selector[:48]}")
        except Exception:  # noqa: BLE001
            continue
    return filled


async def run_site_capture(args: dict[str, Any]) -> dict[str, Any]:
    """Open URL, optionally interact, capture network + storage + script hits."""
    from easy_rev.ai.inspect_dom import snapshot_page, try_accept_consent, try_click_next

    url = str(args["url"])
    engine_name = args.get("engine") or "auto"
    headless = bool(args.get("headless", True))
    wait_ms = int(args.get("wait_ms") or 2000)
    accept_consent = bool(args.get("accept_consent", True))
    multi_step = bool(args.get("multi_step", False))
    max_steps = max(1, min(int(args.get("max_steps") or 5), 10))
    actions = args.get("actions") or []
    capture_bodies = bool(args.get("capture_bodies", True))
    include_scripts = bool(args.get("include_scripts", True))
    download_js = bool(args.get("download_scripts", False))
    search_patterns = args.get("search_patterns") or DEFAULT_SEARCH_PATTERNS
    auto_fill = bool(args.get("auto_fill", False))
    submit = bool(args.get("submit", False))
    screenshot = bool(args.get("screenshot", False))
    max_entries = int(args.get("max_entries") or 200)
    max_body = int(args.get("max_body_bytes") or 64_000)
    url_includes = args.get("url_includes")
    url_excludes = args.get("url_excludes") or [
        "google-analytics",
        "googletagmanager",
        "facebook.net",
        "hotjar",
        "doubleclick",
        "clarity.ms",
    ]
    resource_types = args.get("resource_types")
    min_api_score = int(args.get("min_api_score") or 4)
    redact = bool(args.get("redact_secrets", True))

    if uses_cdp(args):
        engine = resolve_engine_from_args(args)
        engine_name = "cdp"
        profile = profile_from_args(args)
    elif engine_name == "auto":
        try:
            engine = resolve_engine("camoufox")
            engine_name = "camoufox"
        except Exception:  # noqa: BLE001
            engine = resolve_engine("mock")
            engine_name = "mock"
        profile = BrowserProfile(headless=headless)
    else:
        engine = resolve_engine(engine_name)
        profile = BrowserProfile(headless=headless)
    notes: list[str] = []
    account = generate_account(email_domain="example.test")

    capture = NetworkCapture(
        capture_bodies=capture_bodies,
        max_body_bytes=max_body,
        max_entries=max_entries,
        resource_types=set(resource_types) if resource_types else None,
        url_includes=list(url_includes) if url_includes else None,
        url_excludes=list(url_excludes) if url_excludes else None,
        redact_secrets=redact,
    )

    async with engine.session(profile) as session:
        page = session.page

        if engine_name == "mock":
            await page.goto(url)
            return {
                "engine": engine_name,
                "url": url,
                "warning": "mock engine cannot capture real network; install camoufox",
                "account_used": account.model_dump(),
                "network_summary": {"total": 0},
                "apis": [],
                "network": [],
                "scripts": [],
                "script_hits": [],
                "storage": {},
                "suggested_http_steps": [],
                "notes": ["mock engine"],
            }

        capture.attach(page)

        # Install runtime fetch/XHR/WS hooks before heavy interaction
        hook_install: dict[str, Any] = {}
        if bool(args.get("runtime_hooks", True)):
            try:
                from easy_rev.platforms.web.re.runtime_hooks import install_runtime_hooks

                # init script for subsequent navigations
                ctx = getattr(page, "context", None)
                if ctx is not None and hasattr(ctx, "add_init_script"):
                    try:
                        from easy_rev.platforms.web.re.runtime_hooks import INSTALL_HOOKS_JS

                        await ctx.add_init_script(
                            f"(() => {{ ({INSTALL_HOOKS_JS})(); }})();"
                        )
                    except Exception:  # noqa: BLE001
                        pass
                hook_install = await install_runtime_hooks(page)
                notes.append(f"runtime_hooks: {hook_install}")
            except Exception as e:  # noqa: BLE001
                notes.append(f"runtime_hooks failed: {e}")

        # CDP: stay on user's current tab unless navigate=true or URL differs
        cur = getattr(page, "url", None) or ""
        navigate = bool(args.get("navigate", not uses_cdp(args)))
        if uses_cdp(args) and not args.get("navigate"):
            # default attach mode: analyze current page
            navigate = False
            if args.get("url") and url not in cur and cur in {"", "about:blank", "chrome://newtab/"}:
                navigate = True
        if navigate:
            await page.goto(url, wait_until="domcontentloaded")
            await asyncio.sleep(wait_ms / 1000)
        else:
            notes.append(f"cdp attach no-navigate current={cur[:120]}")
            await asyncio.sleep(min(wait_ms, 800) / 1000)
        # re-install after navigation in case init script missed
        if bool(args.get("runtime_hooks", True)):
            try:
                from easy_rev.platforms.web.re.runtime_hooks import install_runtime_hooks

                await install_runtime_hooks(page)
            except Exception:  # noqa: BLE001
                pass

        if accept_consent:
            try:
                clicked = await try_accept_consent(page)
                if clicked:
                    notes.append(f"consent: {clicked[0]}")
                    await asyncio.sleep(min(wait_ms, 1200) / 1000)
            except Exception as e:  # noqa: BLE001
                notes.append(f"consent failed: {e}")

        if auto_fill:
            n = await _auto_fill_account(page, account, notes)
            notes.append(f"auto_fill filled≈{n} fields")

        await _run_inspect_actions(page, actions, notes)

        if multi_step:
            for idx in range(1, max_steps):
                clicked = await try_click_next(page)
                if not clicked:
                    notes.append(f"multi_step stop@{idx}: no next")
                    break
                notes.append(f"multi_step[{idx}] {clicked}")
                await asyncio.sleep(max(wait_ms, 800) / 1000)

        if submit:
            for sel in (
                "button[type=submit]",
                "input[type=submit]",
                "button:has-text('Sign up')",
                "button:has-text('Register')",
                "button:has-text('Create')",
            ):
                try:
                    await page.click(sel, timeout=2500)
                    notes.append(f"submit click {sel}")
                    await asyncio.sleep(max(wait_ms, 1500) / 1000)
                    break
                except Exception:  # noqa: BLE001
                    continue

        # Let late XHR finish
        await asyncio.sleep(0.8)
        await capture.flush(timeout_s=3.0)

        # Runtime hook dump (signing traces + crypto + auto_sign)
        signing: dict[str, Any] = {}
        hook_dump: dict[str, Any] = {}
        auto_sign: dict[str, Any] = {}
        if bool(args.get("runtime_hooks", True)):
            try:
                from easy_rev.platforms.web.re.runtime_hooks import (
                    analyze_signing_traces,
                    dump_runtime_hooks,
                )

                hook_dump = await dump_runtime_hooks(page, max_traces=120)
                signing = analyze_signing_traces(list(hook_dump.get("traces") or []))
            except Exception as e:  # noqa: BLE001
                notes.append(f"signing dump failed: {e}")
            if bool(args.get("auto_sign", True)):
                try:
                    from easy_rev.platforms.web.re.auto_sign import run_auto_sign_analysis

                    auto_sign = await run_auto_sign_analysis(
                        page, sample_url=getattr(page, "url", None) or url
                    )
                    notes.append(f"auto_sign mode={auto_sign.get('mode')}")
                except Exception as e:  # noqa: BLE001
                    notes.append(f"auto_sign failed: {e}")

        dom: dict[str, Any] = {}
        try:
            dom = await snapshot_page(page)
        except Exception as e:  # noqa: BLE001
            notes.append(f"dom snapshot failed: {e}")

        storage = await dump_browser_storage(page)

        script_meta: list[dict[str, Any]] = []
        script_hits: list[dict[str, Any]] = []
        if include_scripts:
            script_meta = await list_page_scripts(page)
            page_url = getattr(page, "url", None) or url
            bundles: list[dict[str, Any]] = []
            # inline first
            inlines = await dump_inline_scripts(page, max_chars=120_000)
            for inl in inlines:
                bundles.append(
                    {
                        "url": f"inline:{inl.get('id') or 'script'}",
                        "content": inl.get("content") or "",
                        "id": inl.get("id"),
                        "length": inl.get("length"),
                    }
                )
            if download_js:
                urls = absolute_script_urls(script_meta, page_url)
                # Prefer same-host scripts first
                from urllib.parse import urlparse

                host = urlparse(page_url).netloc
                urls_sorted = sorted(
                    urls, key=lambda u: (0 if host and host in u else 1, len(u))
                )
                downloaded = await download_scripts(
                    urls_sorted,
                    base_url=page_url,
                    max_scripts=int(args.get("max_scripts") or 12),
                    max_bytes=int(args.get("max_script_bytes") or 400_000),
                )
                for d in downloaded:
                    if d.get("content"):
                        bundles.append(d)
            script_hits = search_scripts(
                bundles,
                list(search_patterns) if isinstance(search_patterns, list) else None,
            )

        # Artifacts
        stamp = time.strftime("%Y%m%d-%H%M%S")
        art = artifacts_dir() / "capture"
        art.mkdir(parents=True, exist_ok=True)
        capture_path = art / f"capture-{stamp}.json"
        har_path = art / f"capture-{stamp}.har"

        apis = api_candidates_as_dicts(
            capture.entries,
            min_score=min_api_score,
            limit=int(args.get("api_limit") or 40),
            redact_secrets=redact,
            include_body=True,
        )
        network_list = capture.to_list(
            api_only=False,
            min_score=0,
            include_body=bool(args.get("include_all_bodies", False)),
            limit=int(args.get("network_limit") or 80),
        )
        # Always include bodies for high-score APIs in `apis`; network list may omit

        from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps

        # Prefer oracle on POSTs when auto_sign found a working signer
        _as_mode = (auto_sign or {}).get("mode") if auto_sign else None
        _best = (auto_sign or {}).get("best_signer") if auto_sign else None
        _need_sign = bool(
            _best
            or _as_mode in {"browser_oracle", "pure_python_with_oracle_fallback"}
            or ((auto_sign or {}).get("crypto_analysis") or {}).get("confidence")
            == "oracle_only"
        )
        smart = smart_suggest_http_steps(
            apis,
            max_steps=int(args.get("suggest_limit") or 10),
            use_browser_cookies=bool(
                args.get("suggest_browser_bridge", True) or _need_sign
            ),
            min_score=min_api_score,
            sign_via_browser=_need_sign,
            signer_path=str(_best) if _best else None,
        )
        suggested = smart.get("steps") or suggest_http_steps(
            apis, max_steps=int(args.get("suggest_limit") or 8)
        )
        dependency_graph = smart.get("graph")

        # Optional deep JS signature analysis
        js_analysis: dict[str, Any] | None = None
        if bool(args.get("analyze_js", True)) and include_scripts:
            from easy_rev.platforms.web.re.js_analyze import analyze_js_text, merge_analyses

            parts: list[dict[str, Any]] = []
            # re-use bundles if we downloaded; else inline only from page
            try:
                from easy_rev.platforms.web.re.scripts import dump_inline_scripts as _dump_inl

                for inl in await _dump_inl(page, max_chars=100_000):
                    c = inl.get("content") or ""
                    if c:
                        parts.append(
                            analyze_js_text(c, source=f"inline:{inl.get('id') or 's'}")
                        )
            except Exception as e:  # noqa: BLE001
                notes.append(f"js_analyze inline failed: {e}")
            if download_js:
                # content may still be in memory from earlier download path — re-download limited
                # NOTE: use module-level imports (nested import of list_page_scripts /
                # absolute_script_urls / download_scripts would make them function-locals
                # and break the earlier include_scripts path with UnboundLocalError).
                try:
                    meta2 = script_meta or await list_page_scripts(page)
                    purl = getattr(page, "url", None) or url
                    dls = await download_scripts(
                        absolute_script_urls(meta2, purl)[:8],
                        base_url=purl,
                        max_scripts=8,
                        max_bytes=300_000,
                    )
                    for d in dls:
                        if d.get("content"):
                            parts.append(analyze_js_text(d["content"], source=str(d.get("url"))))
                except Exception as e:  # noqa: BLE001
                    notes.append(f"js_analyze download failed: {e}")
            if parts:
                js_analysis = merge_analyses(parts)

        payload = {
            "url": getattr(page, "url", None) or url,
            "started_url": url,
            "engine": engine_name,
            "account_used": account.model_dump(),
            "network_summary": capture.summary(),
            "apis": apis,
            "network": network_list,
            "websockets": capture.websockets_summary(),
            "runtime_hooks": {
                "installed": hook_dump.get("installed"),
                "total": hook_dump.get("total"),
                "traces": (hook_dump.get("traces") or [])[-40:],
                "ws": hook_dump.get("ws") or [],
            },
            "signing": signing,
            "auto_sign": {
                "mode": auto_sign.get("mode"),
                "best_signer": auto_sign.get("best_signer"),
                "crypto_analysis": auto_sign.get("crypto_analysis"),
                "signers_working": [
                    w.get("path") for w in (auto_sign.get("signers") or {}).get("working") or []
                ],
                "crypto_event_count": auto_sign.get("crypto_event_count"),
            }
            if auto_sign
            else {},
            "dependency_graph": dependency_graph,
            "scripts": [
                {k: v for k, v in s.items() if k != "content"} for s in (script_meta or [])
            ],
            "script_hits": script_hits[:80],
            "js_analysis": js_analysis,
            "storage": {
                "cookies_compact": storage.get("cookies_compact"),
                "localStorage_keys": list((storage.get("localStorage") or {}).keys()),
                "sessionStorage_keys": list((storage.get("sessionStorage") or {}).keys()),
                "localStorage": storage.get("localStorage"),
                "sessionStorage": storage.get("sessionStorage"),
            },
            "dom": {
                "title": dom.get("title"),
                "url": dom.get("url"),
                "forms": dom.get("forms"),
                "inputs": dom.get("inputs"),
                "buttons": dom.get("buttons"),
                "captchas": dom.get("captchas"),
                "page_errors": dom.get("page_errors"),
                "visible_text": (dom.get("visible_text") or "")[:800],
            },
            "suggested_http_steps": suggested,
            "notes": notes,
        }

        capture_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        har_path.write_text(
            json.dumps(capture.export_har_like(), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        payload["capture_path"] = str(capture_path)
        payload["har_path"] = str(har_path)

        if screenshot:
            png = art / f"capture-{stamp}.png"
            try:
                await page.screenshot(path=str(png), full_page=True)
                payload["screenshot"] = str(png)
            except Exception as e:  # noqa: BLE001
                payload["screenshot_error"] = str(e)

        return payload


async def run_site_scripts(args: dict[str, Any]) -> dict[str, Any]:
    """List / download / search scripts on a page or from explicit URLs."""
    patterns = args.get("search") or args.get("patterns") or DEFAULT_SEARCH_PATTERNS
    if isinstance(patterns, str):
        patterns = [patterns]

    # Offline / URL-only mode
    script_urls = args.get("script_urls") or args.get("urls") or []
    if script_urls and not args.get("url"):
        downloaded = await download_scripts(
            list(script_urls),
            max_scripts=int(args.get("max_scripts") or 20),
            max_bytes=int(args.get("max_bytes") or 500_000),
        )
        hits = search_scripts(downloaded, list(patterns))
        return {
            "mode": "urls",
            "scripts": [
                {
                    "url": d.get("url"),
                    "ok": d.get("ok"),
                    "status": d.get("status"),
                    "bytes": d.get("bytes"),
                    "truncated": d.get("truncated"),
                    "error": d.get("error"),
                }
                for d in downloaded
            ],
            "hits": hits[:100],
            "patterns": patterns,
        }

    url = args.get("url")
    if not url:
        raise ValueError("url or script_urls required")

    engine_name = args.get("engine") or "auto"
    if engine_name == "auto":
        try:
            engine = resolve_engine("camoufox")
            engine_name = "camoufox"
        except Exception:  # noqa: BLE001
            engine = resolve_engine("mock")
            engine_name = "mock"
    else:
        engine = resolve_engine(engine_name)

    profile = BrowserProfile(headless=bool(args.get("headless", True)))
    wait_ms = int(args.get("wait_ms") or 2000)
    download_js = bool(args.get("download", True))

    async with engine.session(profile) as session:
        page = session.page
        if engine_name == "mock":
            await page.goto(str(url))
            return {
                "engine": engine_name,
                "warning": "mock engine — no real scripts",
                "scripts": [],
                "hits": [],
            }
        await page.goto(str(url), wait_until="domcontentloaded")
        await asyncio.sleep(wait_ms / 1000)
        meta = await list_page_scripts(page)
        page_url = getattr(page, "url", None) or str(url)
        bundles: list[dict[str, Any]] = []
        if bool(args.get("include_inline", True)):
            for inl in await dump_inline_scripts(page, max_chars=int(args.get("max_inline_chars") or 150_000)):
                bundles.append(
                    {
                        "url": f"inline:{inl.get('id') or 'script'}",
                        "content": inl.get("content") or "",
                        "length": inl.get("length"),
                    }
                )
        downloaded_info: list[dict[str, Any]] = []
        if download_js:
            urls = absolute_script_urls(meta, page_url)
            downloaded = await download_scripts(
                urls,
                base_url=page_url,
                max_scripts=int(args.get("max_scripts") or 15),
                max_bytes=int(args.get("max_bytes") or 500_000),
            )
            downloaded_info = [
                {
                    "url": d.get("url"),
                    "ok": d.get("ok"),
                    "status": d.get("status"),
                    "bytes": d.get("bytes"),
                    "truncated": d.get("truncated"),
                    "error": d.get("error"),
                }
                for d in downloaded
            ]
            bundles.extend([d for d in downloaded if d.get("content")])

        hits = search_scripts(bundles, list(patterns))
        return {
            "engine": engine_name,
            "url": page_url,
            "script_tags": meta,
            "downloaded": downloaded_info,
            "hits": hits[:120],
            "patterns": patterns,
            "bundle_count": len(bundles),
        }


async def analyze_capture_file(path: str | Path, *, min_score: int = 4) -> dict[str, Any]:
    """Re-analyze a saved capture JSON or HAR-like file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    data = json.loads(p.read_text(encoding="utf-8"))

    # Full capture payload
    if isinstance(data, dict) and "apis" in data:
        apis = data.get("apis") or []
        return {
            "source": str(p),
            "kind": "capture",
            "url": data.get("url"),
            "network_summary": data.get("network_summary"),
            "apis": apis,
            "script_hits": (data.get("script_hits") or [])[:50],
            "suggested_http_steps": data.get("suggested_http_steps")
            or suggest_http_steps(apis),
            "notes": data.get("notes") or [],
        }

    # HAR-like
    entries_raw = []
    if isinstance(data, dict) and "log" in data:
        entries_raw = (data.get("log") or {}).get("entries") or []
    elif isinstance(data, dict) and "network" in data:
        return {
            "source": str(p),
            "kind": "capture_network",
            "apis": api_candidates_as_dicts(
                _entries_from_network_dicts(data.get("network") or []),
                min_score=min_score,
            ),
        }

    from easy_rev.platforms.web.re.network import NetworkEntry

    entries: list[NetworkEntry] = []
    for i, e in enumerate(entries_raw):
        req = e.get("request") or {}
        resp = e.get("response") or {}
        content = resp.get("content") or {}
        post = req.get("postData") or {}
        headers_req = {
            h.get("name"): h.get("value")
            for h in (req.get("headers") or [])
            if isinstance(h, dict) and h.get("name")
        }
        headers_resp = {
            h.get("name"): h.get("value")
            for h in (resp.get("headers") or [])
            if isinstance(h, dict) and h.get("name")
        }
        entries.append(
            NetworkEntry(
                id=i + 1,
                method=str(req.get("method") or "GET"),
                url=str(req.get("url") or ""),
                resource_type=str(e.get("_resourceType") or "xhr"),
                request_headers={str(k): str(v) for k, v in headers_req.items()},
                post_data=(post.get("text") if isinstance(post, dict) else None),
                status=resp.get("status"),
                response_headers={str(k): str(v) for k, v in headers_resp.items()},
                response_body=content.get("text"),
                content_type=str(content.get("mimeType") or ""),
            )
        )
    apis = api_candidates_as_dicts(entries, min_score=min_score)
    return {
        "source": str(p),
        "kind": "har",
        "apis": apis,
        "suggested_http_steps": suggest_http_steps(apis),
        "total_entries": len(entries),
    }


def _entries_from_network_dicts(items: list[dict[str, Any]]) -> list[Any]:
    from easy_rev.platforms.web.re.network import NetworkEntry

    out: list[NetworkEntry] = []
    for i, d in enumerate(items):
        if not isinstance(d, dict):
            continue
        out.append(
            NetworkEntry(
                id=int(d.get("id") or i + 1),
                method=str(d.get("method") or "GET"),
                url=str(d.get("url") or ""),
                resource_type=str(d.get("resource_type") or "xhr"),
                request_headers=dict(d.get("request_headers") or {}),
                post_data=d.get("post_data"),
                status=d.get("status"),
                response_headers=dict(d.get("response_headers") or {}),
                response_body=d.get("response_body"),
                content_type=str(d.get("content_type") or ""),
            )
        )
    return out
