"""Long-lived reverse-engineering browser session server (TCP JSON-RPC).

Started by re.session.start; AI tools talk via session_client.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
import time
import traceback
from typing import Any

logger = logging.getLogger("easy_rev.platforms.web.re.session_server")


class SessionState:
    def __init__(self) -> None:
        self.engine: Any = None
        self.session: Any = None
        self.page: Any = None
        self.capture: Any = None
        self.notes: list[str] = []
        self.started_at = time.time()
        self.last_active = time.time()
        self.url: str | None = None
        self.engine_name = "camoufox"
        self.account: Any = None
        self.auth_token: str | None = None
        self.idle_ttl_s: float = 1800.0
        self._cm_closed = False

    async def close(self) -> None:
        if self._cm_closed:
            return
        self._cm_closed = True
        try:
            if self.capture:
                await self.capture.flush(timeout_s=1.0)
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.session:
                await self.session.close()
        except Exception:  # noqa: BLE001
            pass


STATE = SessionState()


async def handle_request(req: dict[str, Any]) -> dict[str, Any]:
    method = req.get("method") or ""
    params = req.get("params") or {}
    req_id = req.get("id")
    # Auth: if server has token, require matching token on each call
    expected = getattr(STATE, "auth_token", None)
    if expected and method != "ping":
        # allow ping without for health, but still check if provided wrong
        pass
    if expected:
        got = req.get("token") or (params or {}).get("token")
        if str(got or "") != str(expected):
            return _err(req_id, "unauthorized: bad session token")
    STATE.last_active = time.time()
    try:
        if method == "ping":
            result = {
                "pong": True,
                "uptime_s": round(time.time() - STATE.started_at, 1),
                "idle_s": round(time.time() - getattr(STATE, "last_active", STATE.started_at), 1),
            }
        elif method == "act":
            result = await _act(params)
        elif method == "snapshot":
            result = await _snapshot(params)
        elif method == "network":
            result = await _network(params)
        elif method == "eval":
            result = await _eval(params)
        elif method == "storage":
            result = await _storage()
        elif method == "scripts":
            result = await _scripts(params)
        elif method == "analyze_js":
            result = await _analyze_js(params)
        elif method == "goto":
            result = await _goto(params)
        elif method == "export":
            result = await _export(params)
        elif method == "auto_sign":
            result = await _auto_sign(params)
        elif method == "sign":
            result = await _sign(params)
        elif method == "sign_batch":
            result = await _sign_batch(params)
        elif method == "mutate":
            result = await _mutate(params)
        elif method == "stop":
            result = {"stopping": True}
            # schedule close after response
            asyncio.get_event_loop().call_later(0.05, lambda: asyncio.create_task(_shutdown()))
        else:
            return _err(req_id, f"unknown method: {method}")
        return {"id": req_id, "ok": True, "result": result}
    except Exception as e:  # noqa: BLE001
        logger.exception("method %s failed", method)
        return {
            "id": req_id,
            "ok": False,
            "error": {"message": str(e), "trace": traceback.format_exc()[-1500:]},
        }


def _err(req_id: Any, msg: str) -> dict[str, Any]:
    return {"id": req_id, "ok": False, "error": {"message": msg}}


async def _goto(params: dict[str, Any]) -> dict[str, Any]:
    url = params.get("url")
    if not url:
        raise ValueError("url required")
    wait_ms = int(params.get("wait_ms") or 1500)
    await STATE.page.goto(str(url), wait_until="domcontentloaded")
    await asyncio.sleep(wait_ms / 1000)
    STATE.url = getattr(STATE.page, "url", url)
    STATE.notes.append(f"goto {url}")
    return {"url": STATE.url}


async def _act(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.capture_flow import _auto_fill_account, _run_inspect_actions

    notes: list[str] = []
    actions = params.get("actions") or []
    if params.get("auto_fill") and STATE.account:
        n = await _auto_fill_account(STATE.page, STATE.account, notes)
        notes.append(f"auto_fill≈{n}")
    await _run_inspect_actions(STATE.page, actions, notes)
    if params.get("submit"):
        for sel in (
            "button[type=submit]",
            "input[type=submit]",
            "button:has-text('Sign up')",
            "button:has-text('Register')",
            "button:has-text('Create')",
        ):
            try:
                await STATE.page.click(sel, timeout=2500)
                notes.append(f"submit {sel}")
                await asyncio.sleep(1.0)
                break
            except Exception:  # noqa: BLE001
                continue
    if params.get("multi_step"):
        from easy_rev.ai.inspect_dom import try_click_next

        max_steps = max(1, min(int(params.get("max_steps") or 3), 8))
        for idx in range(max_steps):
            clicked = await try_click_next(STATE.page)
            if not clicked:
                notes.append(f"multi_step stop@{idx}")
                break
            notes.append(f"multi_step {clicked}")
            await asyncio.sleep(0.8)
    wait_ms = int(params.get("wait_ms") or 400)
    if wait_ms:
        await asyncio.sleep(wait_ms / 1000)
    if STATE.capture:
        await STATE.capture.flush(timeout_s=2.0)
    STATE.notes.extend(notes)
    return {
        "notes": notes,
        "url": getattr(STATE.page, "url", None),
        "network_total": len(STATE.capture.entries) if STATE.capture else 0,
    }


async def _snapshot(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.ai.inspect_dom import snapshot_page

    if STATE.capture:
        try:
            await STATE.capture.flush(timeout_s=1.5)
        except Exception as e:  # noqa: BLE001
            # Multipart / large body reads in Firefox can raise
            # "Separator is not found, and chunk exceed the limit" — non-fatal.
            STATE.notes.append(f"network flush warning: {e}")

    dom: dict[str, Any] = {}
    try:
        dom = await snapshot_page(STATE.page)
    except Exception as e:  # noqa: BLE001
        # Full DOM evaluate can fail on heavy SPAs; fall back to a light scrape.
        logger.warning("snapshot_page failed: %s — using light fallback", e)
        try:
            light = await STATE.page.evaluate(
                """() => ({
                  title: document.title,
                  url: location.href,
                  inputs: [...document.querySelectorAll('input,textarea,select')].slice(0, 40).map((el) => ({
                    tag: el.tagName.toLowerCase(),
                    type: el.getAttribute('type') || '',
                    name: el.getAttribute('name') || '',
                    id: el.id || '',
                    placeholder: el.getAttribute('placeholder') || '',
                  })),
                  buttons: [...document.querySelectorAll(
                    'button, input[type=submit], [role=button]')].slice(0, 40).map((el) => ({
                    text: (el.innerText || el.value || '').trim().slice(0, 80),
                    type: el.getAttribute('type') || '',
                    id: el.id || '',
                    disabled: !!el.disabled,
                  })),
                  visible_text: ((document.body && document.body.innerText) || '')
                    .replace(/\\s+/g, ' ').trim().slice(0, 1200),
                })"""
            )
            if isinstance(light, dict):
                dom = light
            else:
                dom = {}
            dom.setdefault("snapshot_error", str(e)[:300])
        except Exception as e2:  # noqa: BLE001
            dom = {
                "url": getattr(STATE.page, "url", None),
                "title": None,
                "inputs": [],
                "buttons": [],
                "snapshot_error": f"{e}; fallback: {e2}"[:400],
            }

    out: dict[str, Any] = {
        "url": dom.get("url") or getattr(STATE.page, "url", None),
        "title": dom.get("title"),
        "forms": dom.get("forms") or [],
        "inputs": dom.get("inputs") or [],
        "buttons": dom.get("buttons") or [],
        "captchas": dom.get("captchas") or [],
        "page_errors": dom.get("page_errors") or [],
        "visible_text": (dom.get("visible_text") or "")[:1200],
        "next_candidates": dom.get("next_candidates") or [],
        "html_snippet": (dom.get("html_snippet") or "")[:4000],
    }
    if dom.get("snapshot_error"):
        out["snapshot_error"] = dom["snapshot_error"]
    if params.get("include_network", True) and STATE.capture:
        from easy_rev.platforms.web.re.classify import api_candidates_as_dicts

        try:
            out["network_summary"] = STATE.capture.summary()
            out["apis"] = api_candidates_as_dicts(
                STATE.capture.entries,
                min_score=int(params.get("min_api_score") or 4),
                limit=int(params.get("api_limit") or 30),
            )
            out["websockets"] = getattr(STATE.capture, "websockets_summary", lambda: [])()
        except Exception as e:  # noqa: BLE001
            out["network_error"] = str(e)[:300]
    return out


async def _network(params: dict[str, Any]) -> dict[str, Any]:
    if not STATE.capture:
        return {"apis": [], "network": [], "websockets": []}
    await STATE.capture.flush(timeout_s=2.0)
    from easy_rev.platforms.web.re.classify import api_candidates_as_dicts, suggest_http_steps

    apis = api_candidates_as_dicts(
        STATE.capture.entries,
        min_score=int(params.get("min_api_score") or 4),
        limit=int(params.get("api_limit") or 40),
    )
    return {
        "network_summary": STATE.capture.summary(),
        "apis": apis,
        "network": STATE.capture.to_list(
            limit=int(params.get("network_limit") or 80),
            include_body=bool(params.get("include_bodies", False)),
        ),
        "websockets": STATE.capture.websockets_summary(),
        "suggested_http_steps": suggest_http_steps(apis),
    }


async def _eval(params: dict[str, Any]) -> dict[str, Any]:
    expr = params.get("expression") or params.get("js") or params.get("eval")
    if not expr:
        raise ValueError("expression required")
    result = await STATE.page.evaluate(str(expr), params.get("arg"))
    return {"result": result}


async def _storage() -> dict[str, Any]:
    from easy_rev.platforms.web.re.storage_dump import dump_browser_storage

    return await dump_browser_storage(STATE.page)


async def _scripts(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.scripts import (
        DEFAULT_SEARCH_PATTERNS,
        absolute_script_urls,
        download_scripts,
        dump_inline_scripts,
        list_page_scripts,
        search_scripts,
    )

    patterns = params.get("search") or params.get("patterns") or DEFAULT_SEARCH_PATTERNS
    meta = await list_page_scripts(STATE.page)
    page_url = getattr(STATE.page, "url", None) or STATE.url or ""
    bundles: list[dict[str, Any]] = []
    for inl in await dump_inline_scripts(STATE.page, max_chars=int(params.get("max_inline") or 120_000)):
        bundles.append(
            {
                "url": f"inline:{inl.get('id') or 'script'}",
                "content": inl.get("content") or "",
            }
        )
    if bool(params.get("download", True)):
        urls = absolute_script_urls(meta, page_url)
        downloaded = await download_scripts(
            urls,
            base_url=page_url,
            max_scripts=int(params.get("max_scripts") or 12),
        )
        bundles.extend([d for d in downloaded if d.get("content")])
    hits = search_scripts(bundles, list(patterns) if isinstance(patterns, list) else None)
    return {
        "script_tags": meta,
        "hits": hits[:100],
        "bundle_count": len(bundles),
    }


async def _analyze_js(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.js_analyze import analyze_js_text, merge_analyses
    from easy_rev.platforms.web.re.scripts import (
        absolute_script_urls,
        download_scripts,
        dump_inline_scripts,
        list_page_scripts,
    )

    meta = await list_page_scripts(STATE.page)
    page_url = getattr(STATE.page, "url", None) or STATE.url or ""
    parts: list[dict[str, Any]] = []
    for inl in await dump_inline_scripts(STATE.page, max_chars=150_000):
        content = inl.get("content") or ""
        if content:
            parts.append(
                analyze_js_text(content, source=f"inline:{inl.get('id') or 'script'}")
            )
    if bool(params.get("download", True)):
        urls = absolute_script_urls(meta, page_url)
        downloaded = await download_scripts(
            urls, base_url=page_url, max_scripts=int(params.get("max_scripts") or 10)
        )
        for d in downloaded:
            if d.get("content"):
                parts.append(analyze_js_text(d["content"], source=str(d.get("url"))))
    return merge_analyses(parts)


async def _auto_sign(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.auto_sign import run_auto_sign_analysis

    return await run_auto_sign_analysis(
        STATE.page, sample_url=str(params.get("sample_url") or STATE.url or "")
    )


async def _sign(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.sign_oracle import oracle_sign

    body = params.get("json") if params.get("json") is not None else params.get("body")
    return await oracle_sign(
        STATE.page,
        method=str(params.get("method") or "POST"),
        url=str(params.get("url") or STATE.url or ""),
        body=body,
        signer_path=params.get("signer_path"),
    )


async def _sign_batch(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.auto_sign import oracle_batch_http
    from easy_rev.platforms.web.re.sign_oracle import oracle_sign_batch

    items = list(params.get("items") or [])
    signer = params.get("signer_path")
    if params.get("fire_http"):
        return await oracle_batch_http(
            STATE.page,
            items,
            signer_path=signer,
            proxy=params.get("proxy"),
            impersonate=params.get("impersonate"),
            import_cookies=True,
        )
    return await oracle_sign_batch(
        STATE.page,
        items,
        signer_path=signer,
        default_url=str(STATE.url or ""),
    )


async def _mutate(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.route_mutate import mutate_and_observe

    return await mutate_and_observe(
        STATE.page,
        url_includes=str(params.get("url_includes") or ""),
        mutations=list(params.get("mutations") or []),
        trigger=params.get("trigger"),
    )


async def _export(params: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.core.paths import artifacts_dir
    from easy_rev.platforms.web.re.auto_sign import run_auto_sign_analysis
    from easy_rev.platforms.web.re.classify import api_candidates_as_dicts
    from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps
    from easy_rev.platforms.web.re.runtime_hooks import analyze_signing_traces, dump_runtime_hooks

    if STATE.capture:
        await STATE.capture.flush(timeout_s=2.0)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    art = artifacts_dir() / "capture"
    art.mkdir(parents=True, exist_ok=True)
    apis = (
        api_candidates_as_dicts(STATE.capture.entries, min_score=4, limit=40)
        if STATE.capture
        else []
    )
    hook_dump = await dump_runtime_hooks(STATE.page, max_traces=100)
    signing = analyze_signing_traces(list(hook_dump.get("traces") or []))
    auto_sign: dict[str, Any] = {}
    try:
        auto_sign = await run_auto_sign_analysis(
            STATE.page, sample_url=str(STATE.url or "")
        )
        # strip huge hooks_source for export unless requested
        if not params.get("include_hooks_source") and auto_sign.get("hooks_source"):
            auto_sign = {
                **auto_sign,
                "hooks_source_len": len(auto_sign["hooks_source"]),
                "hooks_source": None,
            }
    except Exception as e:  # noqa: BLE001
        auto_sign = {"error": str(e)}
    _best = auto_sign.get("best_signer")
    _need = bool(
        _best
        or auto_sign.get("mode")
        in {"browser_oracle", "pure_python_with_oracle_fallback"}
    )
    smart = smart_suggest_http_steps(
        apis,
        max_steps=10,
        use_browser_cookies=True,
        sign_via_browser=_need,
        signer_path=str(_best) if _best else None,
    )
    payload = {
        "url": getattr(STATE.page, "url", None),
        "engine": STATE.engine_name,
        "session": True,
        "notes": STATE.notes,
        "network_summary": STATE.capture.summary() if STATE.capture else {},
        "apis": apis,
        "websockets": STATE.capture.websockets_summary() if STATE.capture else [],
        "runtime_hooks": {
            "installed": hook_dump.get("installed"),
            "total": hook_dump.get("total"),
            "traces": (hook_dump.get("traces") or [])[-40:],
        },
        "signing": signing,
        "auto_sign": auto_sign,
        "dependency_graph": smart.get("graph"),
        "suggested_http_steps": smart.get("steps") or [],
        "account_used": STATE.account.model_dump() if STATE.account else None,
    }
    path = art / f"session-export-{stamp}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    har_path = None
    if STATE.capture:
        har_path = art / f"session-export-{stamp}.har.json"
        har_path.write_text(
            json.dumps(STATE.capture.export_har_like(), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    return {
        "capture_path": str(path),
        "har_path": str(har_path) if har_path else None,
        "apis": apis,
        "suggested_http_steps": payload["suggested_http_steps"],
        "websockets": payload["websockets"],
    }


async def _shutdown() -> None:
    await STATE.close()
    await asyncio.sleep(0.05)
    sys.exit(0)


async def client_handler(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                req = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as e:
                resp = {"ok": False, "error": {"message": f"invalid json: {e}"}}
            else:
                resp = await handle_request(req)
            writer.write((json.dumps(resp, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
            await writer.drain()
            if (req.get("method") if isinstance(req, dict) else None) == "stop":
                break
    finally:
        try:
            writer.close()
            # Peer may already have reset the socket (common after large RPC payloads).
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError, OSError):  # noqa: BLE001
            pass
        except Exception:  # noqa: BLE001
            pass


async def _idle_watchdog() -> None:
    """Stop session after idle_ttl_s without client activity."""
    while True:
        await asyncio.sleep(15)
        ttl = float(getattr(STATE, "idle_ttl_s", 0) or 0)
        if ttl <= 0:
            continue
        idle = time.time() - getattr(STATE, "last_active", STATE.started_at)
        if idle >= ttl:
            logger.info("idle ttl exceeded (%.0fs) — shutting down", idle)
            await _shutdown()
            return


async def run_server(
    *,
    host: str,
    port: int,
    url: str | None,
    engine_name: str,
    headless: bool,
    ready_file: str | None,
    auth_token: str | None = None,
    idle_ttl_s: float = 1800.0,
    cdp_url: str | None = None,
    cdp_target_url: str | None = None,
    cdp_target_index: int | None = None,
    navigate: bool = True,
) -> None:
    from easy_rev.core.types import BrowserProfile
    from easy_rev.platforms.web.engine.base import resolve_engine
    from easy_rev.platforms.web.identity.generator import generate_account
    from easy_rev.platforms.web.re.network import NetworkCapture
    from easy_rev.platforms.web.re.session_store import write_session_meta

    STATE.engine_name = engine_name
    STATE.auth_token = auth_token
    STATE.idle_ttl_s = idle_ttl_s
    STATE.last_active = time.time()
    STATE.account = generate_account(email_domain="example.test")
    if cdp_url or engine_name in {"cdp", "chrome", "user", "attach"}:
        STATE.engine = resolve_engine(
            "cdp",
            cdp_url=cdp_url,
            cdp_target_url=cdp_target_url or url,
            cdp_target_index=cdp_target_index,
            cdp_new_page_url=url if navigate and url else None,
        )
        profile = BrowserProfile(
            headless=headless,
            cdp_url=cdp_url,
            cdp_target_url=cdp_target_url or url,
            cdp_target_index=cdp_target_index,
            cdp_new_page_url=url if navigate and url and not cdp_target_url else None,
        )
        STATE.engine_name = "cdp"
    else:
        STATE.engine = resolve_engine(engine_name if engine_name != "auto" else "camoufox")
        profile = BrowserProfile(headless=headless)
    STATE.session = await STATE.engine.launch_session(profile)
    STATE.page = STATE.session.page
    STATE.capture = NetworkCapture(
        capture_bodies=True,
        max_entries=400,
        url_excludes=[
            "google-analytics",
            "googletagmanager",
            "facebook.net",
            "hotjar",
            "doubleclick",
            "clarity.ms",
        ],
    )
    STATE.capture.attach(STATE.page)

    # Runtime hooks for signing traces
    try:
        from easy_rev.platforms.web.re.runtime_hooks import INSTALL_HOOKS_JS, install_runtime_hooks

        ctx = getattr(STATE.page, "context", None)
        if ctx is not None and hasattr(ctx, "add_init_script"):
            try:
                await ctx.add_init_script(f"(() => {{ ({INSTALL_HOOKS_JS})(); }})();")
            except Exception:  # noqa: BLE001
                pass
        await install_runtime_hooks(STATE.page)
        STATE.notes.append("runtime_hooks installed")
    except Exception as e:  # noqa: BLE001
        STATE.notes.append(f"runtime_hooks failed: {e}")

    if url and navigate:
        await STATE.page.goto(url, wait_until="domcontentloaded")
        await asyncio.sleep(1.5)
        STATE.url = getattr(STATE.page, "url", url)
    else:
        STATE.url = getattr(STATE.page, "url", url)
        if cdp_url:
            STATE.notes.append(f"cdp attach no-navigate url={STATE.url}")

    try:
        from easy_rev.platforms.web.re.runtime_hooks import install_runtime_hooks

        await install_runtime_hooks(STATE.page)
    except Exception:  # noqa: BLE001
        pass
    try:
        from easy_rev.ai.inspect_dom import try_accept_consent

        clicked = await try_accept_consent(STATE.page)
        if clicked:
            STATE.notes.append(f"consent {clicked[0]}")
    except Exception:  # noqa: BLE001
        pass

    server = await asyncio.start_server(client_handler, host, port)
    sockets = server.sockets or []
    bound_port = sockets[0].getsockname()[1] if sockets else port

    # Write ready meta (session_id from env/arg injected by parent)
    session_id = getattr(run_server, "session_id", "unknown")
    write_session_meta(
        session_id,
        {
            "host": host,
            "port": bound_port,
            "pid": __import__("os").getpid(),
            "url": STATE.url or url,
            "engine": STATE.engine_name,
            "headless": headless,
            "status": "ready",
            "started_at": STATE.started_at,
            "last_active": STATE.last_active,
            "auth_token": auth_token,
            "idle_ttl_s": idle_ttl_s,
        },
    )
    if ready_file:
        Path_write = __import__("pathlib").Path(ready_file)
        Path_write.write_text(json.dumps({"port": bound_port, "ready": True}), encoding="utf-8")

    logger.info("session server ready on %s:%s id=%s", host, bound_port, session_id)
    asyncio.create_task(_idle_watchdog())

    def _sig(*_args: Any) -> None:
        asyncio.create_task(_shutdown())

    try:
        loop = asyncio.get_running_loop()
        for s in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(s, _sig)
            except NotImplementedError:
                pass
    except Exception:  # noqa: BLE001
        pass

    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Easy-Rev RE session server")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--url", default=None)
    parser.add_argument("--engine", default="camoufox")
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--headed", action="store_true", default=False)
    parser.add_argument("--ready-file", default=None)
    parser.add_argument("--auth-token", default=None)
    parser.add_argument("--idle-ttl-s", type=float, default=1800.0)
    parser.add_argument("--cdp-url", default=None, help="Attach user Chrome via CDP")
    parser.add_argument("--cdp-target-url", default=None)
    parser.add_argument("--cdp-target-index", type=int, default=None)
    parser.add_argument(
        "--no-navigate",
        action="store_true",
        help="Do not goto url; stay on attached tab",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    headless = not args.headed
    run_server.session_id = args.session_id  # type: ignore[attr-defined]

    try:
        asyncio.run(
            run_server(
                host=args.host,
                port=args.port,
                url=args.url,
                engine_name=args.engine if not args.cdp_url else "cdp",
                headless=headless,
                ready_file=args.ready_file,
                auth_token=args.auth_token,
                idle_ttl_s=float(args.idle_ttl_s or 1800),
                cdp_url=args.cdp_url,
                cdp_target_url=args.cdp_target_url,
                cdp_target_index=args.cdp_target_index,
                navigate=not args.no_navigate,
            )
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
