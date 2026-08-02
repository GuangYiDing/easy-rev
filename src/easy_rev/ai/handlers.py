"""Dispatch AI tool calls to platform adapters / web RE helpers."""

from __future__ import annotations

import platform as py_platform
from pathlib import Path
from typing import Any

from easy_rev import __version__
from easy_rev.ai.tools import TOOL_SPECS, tool_schema, tools_catalog
from easy_rev.config import get_settings
from easy_rev.core.paths import artifacts_dir, data_dir, packs_dir
from easy_rev.core.platform import Platform, TargetSpec
from easy_rev.platforms.base import get_adapter


def _ok(data: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    out = {"ok": True, **(data or {}), **extra}
    return out


def _err(msg: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": msg, **extra}


async def call_tool(name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = dict(args or {})
    try:
        return await _dispatch(name, args)
    except Exception as e:  # noqa: BLE001
        return _err(str(e), tool=name)


async def _web_explore(args: dict[str, Any]) -> dict[str, Any]:
    return await _explore({**args, "platform": "web"})


async def _web_capture(args: dict[str, Any]) -> dict[str, Any]:
    return await _capture({**args, "platform": "web"})


async def _desktop_explore(args: dict[str, Any]) -> dict[str, Any]:
    plat = args.get("platform") or (
        "macos" if py_platform.system() == "Darwin" else "windows"
    )
    return await _explore({**args, "platform": plat})


async def _mobile_explore(args: dict[str, Any]) -> dict[str, Any]:
    return await _explore({**args, "platform": args.get("platform") or "android"})


async def _desktop_scripts(args: dict[str, Any]) -> dict[str, Any]:
    return _scripts("desktop", args)


async def _mobile_scripts(args: dict[str, Any]) -> dict[str, Any]:
    return _scripts("mobile", args)


# Registry of tool handlers. Values may be sync or async callables.
TOOL_HANDLERS: dict[str, Any] = {}


def _register_handlers() -> None:
    """Populate TOOL_HANDLERS once function defs exist (called at import end)."""
    TOOL_HANDLERS.update(
        {
            "doctor": _doctor,
            "doctor.preflight": _doctor_preflight,
            "doctor.fix": _doctor_fix,
            "doctor.catalog": _doctor_catalog,
            "explore": _explore,
            "capture": _capture,
            "analyze": _analyze,
            "web.explore": _web_explore,
            "web.capture": _web_capture,
            "web.bridge.start": _bridge_start,
            "web.bridge.status": _bridge_status,
            "web.analyze_js": _analyze_js,
            "desktop.ps": _desktop_ps,
            "desktop.explore": _desktop_explore,
            "mobile.devices": _mobile_devices,
            "mobile.apps": _mobile_apps,
            "mobile.explore": _mobile_explore,
            "pack.init": _pack_init,
            "pack.list": lambda args: _pack_list(),
            "pack.from_capture": _pack_from_capture,
            "web.dependency_graph": _web_dependency_graph,
            "desktop.scripts": _desktop_scripts,
            "mobile.scripts": _mobile_scripts,
            "web.sign_synth": _web_sign_synth,
            "web.diff_capture": _web_diff_capture,
            "web.offline_chain": _web_offline_chain,
            "web.diagnose": _web_diagnose,
            "web.har_export": _web_har_export,
            "web.session.start": _web_session_start,
            "web.session.stop": _web_session_stop,
            "web.session.list": _web_session_list,
            "pack.validate": _pack_validate,
            "pack.run": _pack_run,
            "route": _route,
            "route.table": lambda args: _route_table(),
            "case.init": _case_init,
            "case.guard": _case_guard,
            "evidence.append": _evidence_append,
            "finding.append": _finding_append,
            "path.append": _path_append,
            "journal.write": _journal_write,
            "journal.search": _journal_search,
            "skill.list": lambda args: _skill_list(),
            "frida.session.start": _frida_session_start,
            "frida.session.stop": _frida_session_stop,
            "frida.session.list": _frida_session_list,
            "frida.session.drain": _frida_session_drain,
            "frida.session.eval": _frida_session_eval,
        }
    )


async def _dispatch(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if not TOOL_HANDLERS:
        _register_handlers()
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return _err(f"unknown tool: {name}", available=[t["name"] for t in TOOL_SPECS])
    import inspect

    # pack.list registered as zero-arg lambda
    try:
        result = handler(args)
    except TypeError:
        result = handler()
    if inspect.isawaitable(result):
        result = await result
    return result


def _doctor_preflight(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.core.deps import preflight

    return preflight(
        args.get("platform") or "all",
        path=args.get("path"),
        include_optional=bool(args.get("include_optional", True)),
    )


def _doctor_fix(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.core.deps import fix_deps

    ids = args.get("ids")
    if isinstance(ids, str):
        ids = [x.strip() for x in ids.split(",") if x.strip()]
    return fix_deps(
        ids if isinstance(ids, list) else None,
        platform=args.get("platform") or "all",
        allow_system=bool(args.get("allow_system", False)),
        dry_run=bool(args.get("dry_run", False)),
        timeout_s=float(args.get("timeout_s") or 600),
    )


def _doctor_catalog(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.core.deps import catalog_public

    items = catalog_public()
    platform = args.get("platform")
    if platform and platform != "all":
        items = [
            i
            for i in items
            if platform in (i.get("platforms") or []) or "all" in (i.get("platforms") or [])
        ]
    return _ok(deps=items, count=len(items))


async def _doctor(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.core.deps import preflight

    which = (args.get("platform") or "all").lower()
    platforms = {
        "web": Platform.WEB,
        "windows": Platform.WINDOWS,
        "macos": Platform.MACOS,
        "android": Platform.ANDROID,
        "ios": Platform.IOS,
    }
    s = get_settings()
    result: dict[str, Any] = {
        "ok": True,
        "version": __version__,
        "data_dir": str(s.data_dir),
        "artifacts_dir": str(artifacts_dir()),
        "host": {
            "system": py_platform.system(),
            "machine": py_platform.machine(),
            "python": py_platform.python_version(),
        },
        "platforms": {},
    }
    targets = list(platforms.items()) if which == "all" else [(which, platforms[which])]
    for key, plat in targets:
        try:
            adapter = get_adapter(plat)
            result["platforms"][key] = await adapter.doctor()
        except Exception as e:  # noqa: BLE001
            result["platforms"][key] = {"error": str(e)}

    # Unified preflight (catalog-driven readiness + fixable list)
    pf = preflight(which, path=args.get("path"), include_optional=bool(args.get("include_optional", True)))
    # merge score/ready into platform blocks
    for key, pinfo in (pf.get("platforms") or {}).items():
        if key in result["platforms"] and isinstance(result["platforms"][key], dict):
            result["platforms"][key]["score"] = pinfo.get("score")
            result["platforms"][key]["ready"] = pinfo.get("ready")
            result["platforms"][key]["preflight_missing"] = pinfo.get("missing")
            result["platforms"][key]["preflight_present"] = pinfo.get("present")
            result["platforms"][key]["checks"] = pinfo.get("checks")
        else:
            result["platforms"][key] = pinfo

    result["ready"] = pf.get("ready")
    result["missing"] = list(pf.get("missing_required") or []) + list(pf.get("missing_recommended") or [])
    result["missing_required"] = pf.get("missing_required") or []
    result["missing_recommended"] = pf.get("missing_recommended") or []
    result["missing_optional"] = pf.get("missing_optional") or []
    result["fixable"] = pf.get("fixable") or []
    result["install_hints"] = pf.get("install_hints") or []
    result["next_steps"] = pf.get("next_steps") or []
    result["summary"] = pf.get("summary") or {}
    result["status_legend"] = {
        "attached": "live browser/Frida session",
        "dry_run": "optional dep missing; contract ok, not attached",
        "offline": "web offline protocol chain (no browser)",
        "degraded": "fell back from preferred path",
        "error": "attempted and failed",
        "static": "static-only analysis",
    }
    result["ai_hint"] = (
        "To auto-install fixable Python deps: easy-rev doctor --fix"
        " or ai call doctor.fix -i '{\"ids\":[\"frida\",\"camoufox\"]}'"
    )
    return result


def _target_from_args(args: dict[str, Any]) -> TargetSpec:
    plat = Platform(str(args.get("platform") or "web").lower())
    return TargetSpec(
        platform=plat,
        url=args.get("url"),
        binary=args.get("binary"),
        process=args.get("process"),
        package=args.get("package"),
        device=args.get("device"),
        name=args.get("name"),
        meta={k: v for k, v in args.items() if k not in {
            "platform", "url", "binary", "process", "package", "device", "name"
        }},
    )


async def _explore(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.core.deps import preflight
    from easy_rev.util.redact import redact_obj

    target = _target_from_args(args)
    adapter = get_adapter(target.platform)
    # Preflight snapshot (non-blocking) so AI sees missing tools before/with explore
    plat = target.platform.value
    if plat == "web":
        path_hint = "browser"
    elif plat in {"android", "ios"} and (args.get("package") or args.get("attach", True)):
        path_hint = "dynamic"
    elif plat in {"windows", "macos"} and (args.get("process") or args.get("attach", True)):
        path_hint = "dynamic"
    else:
        path_hint = "static"
    pf = preflight(plat, path=path_hint)

    # pass through remaining kwargs
    kwargs = {k: v for k, v in args.items() if k not in {"platform"}}
    result = await adapter.explore(target, **kwargs)
    out = result.to_envelope()
    # Always keep artifacts/findings even if empty for contract stability
    out["artifacts"] = [a.model_dump(mode="json") for a in result.artifacts]
    out["findings"] = dict(result.findings or {})
    out["next_steps"] = list(result.next_steps or [])
    out["blocking_issues"] = list(result.blocking_issues or [])
    preflight_block = {
        "path": path_hint,
        "ready": pf.get("ready"),
        "score": ((pf.get("platforms") or {}).get(plat) or {}).get("score"),
        "missing": ((pf.get("platforms") or {}).get(plat) or {}).get("missing"),
        "fixable": pf.get("fixable"),
        "install_hints": pf.get("install_hints"),
        "next_steps": pf.get("next_steps"),
    }
    out["preflight"] = preflight_block
    out["findings"] = {**out["findings"], "preflight_ready": pf.get("ready")}
    # Surface preflight next steps when explore itself has few tips
    if preflight_block.get("next_steps") and not out.get("next_steps"):
        out["next_steps"] = list(preflight_block["next_steps"] or [])
    # Optional redaction for agent-safe sharing
    if args.get("redact") or args.get("redact_sensitive"):
        out = redact_obj(out)
    # Ensure status legend-friendly fields always present
    out.setdefault("status", result.status or ("error" if not result.ok else "static"))
    out.setdefault("attached", bool(result.attached))
    out.setdefault("dry_run", bool(result.dry_run))
    out.setdefault("degraded", bool(result.degraded))
    out.setdefault("confidence", result.confidence or "low")
    return out


async def _capture(args: dict[str, Any]) -> dict[str, Any]:
    target = _target_from_args(args)
    adapter = get_adapter(target.platform)
    kwargs = {k: v for k, v in args.items() if k not in {"platform"}}
    return await adapter.capture(target, **kwargs)


async def _analyze(args: dict[str, Any]) -> dict[str, Any]:
    target = _target_from_args(args)
    adapter = get_adapter(target.platform)
    kwargs = {k: v for k, v in args.items() if k not in {"platform"}}
    return await adapter.analyze(target, **kwargs)


async def _bridge_start(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.extension_bridge import start_bridge

    s = get_settings()
    host = args.get("host") or s.bridge_host
    port = int(args.get("port") or s.bridge_port)
    info = start_bridge(host=host, port=port, blocking=False)
    return info if isinstance(info, dict) else _ok(bridge=info)


async def _bridge_status(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.extension_bridge import bridge_status

    return _ok(**bridge_status())


async def _analyze_js(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.js_analyze import analyze_js_text

    text = args.get("text") or ""
    if text:
        return _ok(analyze_js_text(text))
    url = args.get("url")
    if not url:
        return _err("text or url required")
    # use explore's script path lightly
    import httpx

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        r = await client.get(url)
        r.raise_for_status()
        return _ok(analyze_js_text(r.text), url=url)


def _desktop_ps(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.desktop.common.frida_session import list_processes

    procs = list_processes(host=args.get("host"))
    return _ok(processes=procs, count=len(procs))


async def _mobile_devices(args: dict[str, Any]) -> dict[str, Any]:
    plat = Platform((args.get("platform") or "android").lower())
    adapter = get_adapter(plat)
    info = await adapter.doctor()
    return _ok(
        devices=info.get("devices") or [],
        frida_devices=info.get("frida_devices") or [],
        tools=info.get("tools") or {},
    )


def _mobile_apps(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.mobile.common.frida_session import list_apps

    apps = list_apps(device=args.get("device"))
    return _ok(apps=apps, count=len(apps))


def _pack_init(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.pack.template import init_pack

    pack_id = args.get("pack_id")
    if not pack_id:
        return _err("pack_id required")
    dest = Path(args.get("dest") or f"./packs/{pack_id}")
    path = init_pack(
        dest,
        pack_id=pack_id,
        name=args.get("name"),
        description=args.get("description") or "",
        platform=args.get("platform") or "web",
        with_hooks=bool(args.get("with_hooks")),
        with_ops=bool(args.get("with_ops", True)),
    )
    return _ok(path=str(path), pack_id=pack_id)


def _pack_list() -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    for root in [Path("packs"), packs_dir(), data_dir() / "packs"]:
        if not root.exists():
            continue
        for p in sorted(root.iterdir()):
            if (p / "pack.yaml").is_file():
                found.append({"id": p.name, "path": str(p.resolve())})
    return _ok(packs=found, count=len(found))


def _pack_from_capture(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.draft_protocol import write_protocol_pack

    capture_path = args.get("capture_path")
    if not capture_path:
        return _err("capture_path required")
    cap = Path(capture_path)
    if not cap.is_file():
        return _err(f"capture not found: {capture_path}")
    pack_id = args.get("pack_id")
    if not pack_id:
        pack_id = cap.stem.replace("capture-", "from-")[:64] or "from-capture"
    dest = Path(args.get("dest") or f"./packs/{pack_id}")
    out = write_protocol_pack(
        pack_path=dest,
        pack_id=pack_id,
        name=args.get("name") or pack_id,
        capture_path=cap,
        hybrid=bool(args.get("hybrid", False)),
        max_apis=int(args.get("max_apis") or 8),
        min_score=int(args.get("min_score") or 4),
        impersonate=args.get("impersonate") or "chrome120",
    )
    return _ok(out if isinstance(out, dict) else {"result": out}, pack_id=pack_id, path=str(dest))


def _web_dependency_graph(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps

    apis = args.get("apis")
    if not apis and args.get("capture_path"):
        import json

        data = json.loads(Path(args["capture_path"]).read_text(encoding="utf-8"))
        apis = data.get("apis") or []
    if not apis:
        return _err("apis or capture_path required")
    min_score = int(args.get("min_score") or 0)
    ranked = [a for a in apis if int(a.get("score") or 0) >= min_score]
    steps = smart_suggest_http_steps(ranked if ranked else apis)
    return _ok(
        steps=steps if isinstance(steps, list) else steps,
        api_count=len(apis),
    )


def _scripts(kind: str, args: dict[str, Any]) -> dict[str, Any]:
    if kind == "desktop":
        from easy_rev.platforms.desktop.scripts import list_scripts, load_script
    else:
        from easy_rev.platforms.mobile.scripts import list_scripts, load_script

    names = list_scripts()
    out: dict[str, Any] = {"scripts": names, "platform": kind, "count": len(names)}
    name = args.get("name")
    if name:
        try:
            src = load_script(str(name))
        except FileNotFoundError as e:
            return _err(str(e), scripts=names, platform=kind)
        out["name"] = name if str(name).endswith(".js") else f"{name}.js"
        out["source"] = src
        out["source_len"] = len(src)
    return _ok(**out)


def _web_sign_synth(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.sign_synth import (
        analyze_crypto_events,
        synthesize_sign_request_python,
    )

    events = args.get("events")
    if events is None:
        return _err("events required")
    if not isinstance(events, list):
        return _err("events must be a list")
    analysis = analyze_crypto_events(events)
    out: dict[str, Any] = {"analysis": analysis, **analysis}
    if args.get("synthesize", True):
        code = synthesize_sign_request_python(analysis)
        out["sign_request_python"] = code
        out["recoverable"] = analysis.get("recoverable") or []
    return _ok(**out)


def _web_diff_capture(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.diff_capture import diff_captures

    a = args.get("a_path") or args.get("a")
    b = args.get("b_path") or args.get("b")
    if a is None or b is None:
        return _err("a/a_path and b/b_path required")
    # allow inline dict
    if isinstance(a, dict) or isinstance(b, dict):
        result = diff_captures(a, b, focus=args.get("focus"))
        return _ok(**result)
    # path strings
    pa, pb = Path(str(a)), Path(str(b))
    if not pa.is_file():
        return _err(f"capture A not found: {a}")
    if not pb.is_file():
        return _err(f"capture B not found: {b}")
    result = diff_captures(pa, pb, focus=args.get("focus"))
    return _ok(**result)


def _web_offline_chain(args: dict[str, Any]) -> dict[str, Any]:
    """Connect classify → graph → from_capture pack → optional sign_synth (no browser)."""
    import json

    from easy_rev.platforms.web.re.classify import classify_entry, rank_api_candidates
    from easy_rev.platforms.web.re.dependency_graph import smart_suggest_http_steps
    from easy_rev.platforms.web.re.draft_protocol import write_protocol_pack
    from easy_rev.platforms.web.re.network import NetworkEntry
    from easy_rev.platforms.web.re.sign_synth import (
        analyze_crypto_events,
        synthesize_sign_request_python,
    )

    capture: dict[str, Any]
    if args.get("capture") and isinstance(args["capture"], dict):
        capture = args["capture"]
        cap_path: Path | None = None
    elif args.get("capture_path"):
        cap_path = Path(args["capture_path"])
        if not cap_path.is_file():
            return _err(f"capture not found: {args['capture_path']}")
        capture = json.loads(cap_path.read_text(encoding="utf-8"))
    else:
        return _err("capture_path or capture required")

    raw_apis = [a for a in (capture.get("apis") or []) if isinstance(a, dict)]
    entries: list[NetworkEntry] = []
    for i, a in enumerate(raw_apis):
        entries.append(
            NetworkEntry(
                id=int(a.get("id") or i + 1),
                method=str(a.get("method") or "GET"),
                url=str(a.get("url") or ""),
                resource_type=str(a.get("resource_type") or "xhr"),
                status=a.get("status"),
                request_headers=a.get("request_headers") or {},
                post_data=a.get("post_data"),
                content_type=a.get("content_type"),
            )
        )
    ranked = rank_api_candidates(entries, min_score=int(args.get("min_score") or 1))
    classified = [
        {
            "method": e.method,
            "url": e.url,
            "score": classify_entry(e).score,
            "tags": list(classify_entry(e).tags),
            "post_data": e.post_data,
            "status": e.status,
            "request_headers": e.request_headers,
        }
        for e in entries
    ]
    # enrich raw_apis scores if missing
    apis_for_graph = []
    for a, c in zip(raw_apis, classified, strict=False):
        merged = {**a, **{k: v for k, v in c.items() if k not in a or a.get(k) in (None, [], 0)}}
        if "score" not in merged or not merged.get("score"):
            merged["score"] = c["score"]
        if not merged.get("tags"):
            merged["tags"] = c["tags"]
        apis_for_graph.append(merged)

    graph = smart_suggest_http_steps(apis_for_graph, min_score=int(args.get("min_score") or 0))

    pack_out = None
    pack_path = None
    write_pack = args.get("write_pack", True)
    if write_pack:
        pack_id = args.get("pack_id") or "offline-chain"
        dest = Path(args.get("dest") or f"./packs/{pack_id}")
        # ensure capture on disk for write_protocol_pack
        if cap_path is None:
            dest.mkdir(parents=True, exist_ok=True)
            cap_path = dest / "_capture.json"
            cap_path.write_text(json.dumps(capture, ensure_ascii=False, indent=2), encoding="utf-8")
        pack_out = write_protocol_pack(
            pack_path=dest,
            pack_id=pack_id,
            capture_path=cap_path,
            hybrid=bool(args.get("hybrid", False)),
        )
        pack_path = str(dest)

    crypto_events = capture.get("crypto_events") or capture.get("crypto_hooks") or []
    sign = None
    if crypto_events:
        analysis = analyze_crypto_events(crypto_events)
        sign = {
            "analysis": analysis,
            "sign_request_python": synthesize_sign_request_python(analysis),
        }

    return _ok(
        chain=["classify", "dependency_graph", "pack" if write_pack else "pack_skipped", "sign_synth"],
        classified_count=len(classified),
        ranked_count=len(ranked),
        top_apis=classified[:8],
        graph=graph if isinstance(graph, dict) else {"steps": graph},
        pack=pack_out if isinstance(pack_out, dict) else pack_out,
        pack_path=pack_path,
        sign=sign,
        url=capture.get("url"),
    )


async def _web_diagnose(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.diagnose_proto import (
        diagnose_capture_path,
        diagnose_http_message,
        diagnose_protocol_job,
    )

    if args.get("capture_path"):
        path = Path(args["capture_path"])
        if not path.is_file():
            return _err(f"capture not found: {path}")
        out = diagnose_capture_path(path)
        return _ok(**out)
    if args.get("job_id"):
        out = await diagnose_protocol_job(str(args["job_id"]))
        return _ok(**out)
    if args.get("message") is not None or args.get("status") is not None:
        tips = diagnose_http_message(
            args.get("message"),
            {"last_http_status": args.get("status")},
        )
        return _ok(suggestions=tips)
    return _err("capture_path, job_id, or message/status required")


def _web_har_export(args: dict[str, Any]) -> dict[str, Any]:
    import json
    from urllib.parse import urlparse

    from easy_rev.platforms.web.re.network import NetworkCapture, NetworkEntry

    cap_path = args.get("capture_path")
    if not cap_path:
        return _err("capture_path required")
    p = Path(cap_path)
    if not p.is_file():
        return _err(f"capture not found: {cap_path}")
    data = json.loads(p.read_text(encoding="utf-8"))
    apis = [a for a in (data.get("apis") or []) if isinstance(a, dict)]
    entries: list[NetworkEntry] = []
    for i, a in enumerate(apis):
        entries.append(
            NetworkEntry(
                id=int(a.get("id") or i + 1),
                method=str(a.get("method") or "GET"),
                url=str(a.get("url") or ""),
                resource_type=str(a.get("resource_type") or "xhr"),
                status=a.get("status"),
                request_headers=a.get("request_headers") or {},
                post_data=a.get("post_data") if isinstance(a.get("post_data"), str) else (
                    json.dumps(a.get("post_data")) if a.get("post_data") is not None else None
                ),
                content_type=str(a.get("content_type") or ""),
                response_body=a.get("response_body") if isinstance(a.get("response_body"), str) else None,
            )
        )
    capture = NetworkCapture()
    capture.entries = entries
    from easy_rev.platforms.web.re.har_export import capture_to_har

    har = capture_to_har(
        capture,
        page_url=data.get("url"),
        title=args.get("title") or "easy-rev capture",
    )
    dest = args.get("dest")
    if dest:
        out_path = Path(dest)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(har, ensure_ascii=False, indent=2), encoding="utf-8")
        return _ok(path=str(out_path), entry_count=len(entries), host=urlparse(str(data.get("url") or "")).netloc)
    return _ok(har=har, entry_count=len(entries))


async def _web_session_start(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.session_client import session_start

    try:
        out = await session_start(args)
        if isinstance(out, dict):
            out.setdefault("ok", True)
            return out if "ok" in out else _ok(**out)
        return _ok(result=out)
    except Exception as e:  # noqa: BLE001
        return _err(
            str(e),
            status="error",
            hint="pip install 'easy-rev[web]' && python -m camoufox fetch; or pass cdp_url=",
        )


async def _web_session_stop(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.session_client import session_stop

    sid = args.get("session_id")
    if not sid:
        return _err("session_id required")
    try:
        out = await session_stop(str(sid))
        if isinstance(out, dict) and "ok" in out:
            return out
        return _ok(**(out if isinstance(out, dict) else {"result": out}))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


async def _web_session_list(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.web.re.session_client import session_list

    try:
        out = await session_list()
        if isinstance(out, dict) and "ok" in out:
            return out
        return _ok(**(out if isinstance(out, dict) else {"sessions": out}))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


def _pack_validate(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.pack.validate import validate_pack

    path = args.get("path")
    if not path:
        return _err("path required")
    result = validate_pack(path)
    return _ok(**result) if result.get("ok") else {**result, "ok": False}


async def _pack_run(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.pack.runner import run_pack

    path = args.get("path")
    if not path:
        return _err("path required")
    result = await run_pack(
        path,
        dry_run=bool(args.get("dry_run", True)),
        vars_override=args.get("vars") if isinstance(args.get("vars"), dict) else None,
        max_steps=int(args.get("max_steps") or 20),
    )
    return result if "ok" in result else _ok(**result)


def _frida_session_start(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.common.frida_live import start_session

    kind = str(args.get("kind") or "desktop").lower()
    if kind not in {"desktop", "mobile"}:
        return _err("kind must be desktop|mobile")
    target = args.get("target")
    if not target:
        return _err("target required (process or package)")
    platform = str(
        args.get("platform")
        or ("macos" if kind == "desktop" else "android")
    )
    return start_session(
        kind=kind,  # type: ignore[arg-type]
        platform=platform,
        target=str(target),
        scripts=list(args.get("scripts") or []),
        spawn=bool(args.get("spawn", True)),
        device=args.get("device"),
        host=args.get("host"),
        session_id=args.get("session_id"),
    )


def _frida_session_stop(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.common.frida_live import stop_session

    sid = args.get("session_id")
    if not sid:
        return _err("session_id required")
    return stop_session(str(sid))


def _frida_session_list(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.common.frida_live import list_sessions

    sessions = list_sessions()
    return _ok(sessions=sessions, count=len(sessions))


def _frida_session_drain(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.common.frida_live import drain_messages

    sid = args.get("session_id")
    if not sid:
        return _err("session_id required")
    return drain_messages(
        str(sid),
        since=int(args.get("since") or 0),
        limit=int(args.get("limit") or 500),
    )


def _frida_session_eval(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.platforms.common.frida_live import eval_js

    sid = args.get("session_id")
    source = args.get("source")
    if not sid or source is None:
        return _err("session_id and source required")
    return eval_js(str(sid), str(source))




def _route(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.routing import master_route

    hint = args.get("hint") or args.get("task") or ""
    if not hint:
        return _err("hint required")
    return master_route(str(hint), platform=args.get("platform"))


def _route_table() -> dict[str, Any]:
    from easy_rev.skill.routing import route_table

    rows = route_table()
    return _ok(routes=rows, count=len(rows))


def _case_init(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.case import case_init

    return case_init(
        hint=str(args.get("hint") or ""),
        case_name=args.get("case_name"),
        dest=args.get("dest"),
        platform=args.get("platform"),
        auth_granted=bool(args.get("auth_granted")),
        auth_basis=str(args.get("auth_basis") or "unknown"),
        network_profile=str(args.get("network_profile") or "offline"),
        target=args.get("target"),
        assets=list(args.get("assets") or []) or None,
        with_pack=bool(args.get("with_pack", True)),
        with_hooks=bool(args.get("with_hooks")),
        notes=str(args.get("notes") or ""),
    )


def _case_guard(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.case import case_guard

    path = args.get("path")
    if not path:
        return _err("path required")
    return case_guard(path, force=bool(args.get("force")))


def _evidence_append(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.evidence import append_evidence

    path = args.get("path")
    title = args.get("title")
    if not path or not title:
        return _err("path and title required")
    return append_evidence(
        path,
        title=str(title),
        repro_command=str(args.get("repro_command") or ""),
        source_type=str(args.get("source_type") or "command"),
        source_ref=str(args.get("source_ref") or ""),
        raw_excerpt=str(args.get("raw_excerpt") or ""),
        content_hash=str(args.get("content_hash") or ""),
        evidence_id=args.get("evidence_id"),
    )


def _finding_append(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.evidence import append_finding

    path = args.get("path")
    title = args.get("title")
    if not path or not title:
        return _err("path and title required")
    return append_finding(
        path,
        title=str(title),
        severity=str(args.get("severity") or "info"),
        category=str(args.get("category") or "reverse_algo"),
        status=str(args.get("status") or "candidate"),
        evidence_ids=list(args.get("evidence_ids") or []),
        location=str(args.get("location") or ""),
        impact=str(args.get("impact") or ""),
        confidence=str(args.get("confidence") or "medium"),
        repro_steps=list(args.get("repro_steps") or []),
        remediation=str(args.get("remediation") or "n/a"),
        finding_id=args.get("finding_id"),
    )


def _path_append(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.evidence import append_path

    path = args.get("path")
    title = args.get("title")
    if not path or not title:
        return _err("path and title required")
    steps = args.get("steps") or []
    if not isinstance(steps, list):
        steps = []
    return append_path(
        path,
        title=str(title),
        path_type=str(args.get("path_type") or "callflow"),
        start=str(args.get("start") or ""),
        goal=str(args.get("goal") or ""),
        steps=[s if isinstance(s, dict) else {"action": str(s)} for s in steps],
        residual_risks=str(args.get("residual_risks") or ""),
        path_id=args.get("path_id"),
    )


def _journal_write(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.journal import journal_write

    title = args.get("title")
    summary = args.get("summary")
    if not title or not summary:
        return _err("title and summary required")
    return journal_write(
        title=str(title),
        summary=str(summary),
        tags=list(args.get("tags") or []),
        platform=args.get("platform"),
        pattern=str(args.get("pattern") or ""),
        commands=list(args.get("commands") or []),
        pitfalls=list(args.get("pitfalls") or []),
        root=args.get("root"),
    )


def _journal_search(args: dict[str, Any]) -> dict[str, Any]:
    from easy_rev.skill.journal import journal_search

    return journal_search(
        str(args.get("query") or ""),
        platform=args.get("platform"),
        limit=int(args.get("limit") or 10),
        root=args.get("root"),
    )


def _skill_list() -> dict[str, Any]:
    roots = [Path("skills"), Path(__file__).resolve().parents[3] / "skills"]
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for base in roots:
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("SKILL.md")):
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            name = p.parent.name
            desc = ""
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()[:40]:
                if line.startswith("description:"):
                    desc = line.split(":", 1)[1].strip()
                    break
                if line.startswith("# "):
                    desc = line[2:].strip()
            found.append({"name": name, "path": str(p), "description": desc})
        # also master routing
        master = base / "MASTER-ROUTING.md"
        if master.is_file():
            key = str(master.resolve())
            if key not in seen:
                seen.add(key)
                found.insert(0, {"name": "MASTER-ROUTING", "path": str(master), "description": "PRIMARY ladder"})
    return _ok(skills=found, count=len(found))

_register_handlers()

__all__ = ["call_tool", "tools_catalog", "tool_schema", "TOOL_HANDLERS"]
