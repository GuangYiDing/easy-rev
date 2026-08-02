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


async def _dispatch(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "doctor":
        return await _doctor(args)
    if name == "doctor.preflight":
        return _doctor_preflight(args)
    if name == "doctor.fix":
        return _doctor_fix(args)
    if name == "doctor.catalog":
        return _doctor_catalog(args)
    if name == "explore":
        return await _explore(args)
    if name == "capture":
        return await _capture(args)
    if name == "analyze":
        return await _analyze(args)
    if name == "web.explore":
        args = {**args, "platform": "web"}
        return await _explore(args)
    if name == "web.capture":
        args = {**args, "platform": "web"}
        return await _capture(args)
    if name == "web.bridge.start":
        return await _bridge_start(args)
    if name == "web.bridge.status":
        return await _bridge_status(args)
    if name == "web.analyze_js":
        return await _analyze_js(args)
    if name == "desktop.ps":
        return _desktop_ps(args)
    if name == "desktop.explore":
        plat = args.get("platform") or (
            "macos" if py_platform.system() == "Darwin" else "windows"
        )
        args = {**args, "platform": plat}
        return await _explore(args)
    if name == "mobile.devices":
        return await _mobile_devices(args)
    if name == "mobile.apps":
        return _mobile_apps(args)
    if name == "mobile.explore":
        args = {**args, "platform": args.get("platform") or "android"}
        return await _explore(args)
    if name == "pack.init":
        return _pack_init(args)
    if name == "pack.list":
        return _pack_list()
    if name == "pack.from_capture":
        return _pack_from_capture(args)
    if name == "web.dependency_graph":
        return _web_dependency_graph(args)
    if name == "desktop.scripts":
        return _scripts("desktop", args)
    if name == "mobile.scripts":
        return _scripts("mobile", args)
    if name == "web.sign_synth":
        return _web_sign_synth(args)
    if name == "web.diff_capture":
        return _web_diff_capture(args)
    if name == "web.offline_chain":
        return _web_offline_chain(args)
    if name == "web.diagnose":
        return await _web_diagnose(args)
    if name == "web.har_export":
        return _web_har_export(args)
    if name == "web.session.start":
        return await _web_session_start(args)
    if name == "web.session.stop":
        return await _web_session_stop(args)
    if name == "web.session.list":
        return await _web_session_list(args)
    if name == "pack.validate":
        return _pack_validate(args)
    if name == "pack.run":
        return await _pack_run(args)
    if name == "frida.session.start":
        return _frida_session_start(args)
    if name == "frida.session.stop":
        return _frida_session_stop(args)
    if name == "frida.session.list":
        return _frida_session_list(args)
    if name == "frida.session.drain":
        return _frida_session_drain(args)
    if name == "frida.session.eval":
        return _frida_session_eval(args)
    return _err(f"unknown tool: {name}", available=[t["name"] for t in TOOL_SPECS])


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

    target = _target_from_args(args)
    adapter = get_adapter(target.platform)
    # Preflight snapshot (non-blocking) so AI sees missing tools before/with explore
    plat = target.platform.value
    path_hint = None
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
    out = {
        "ok": result.ok,
        "platform": result.platform,
        "target": result.target,
        "recommendation": result.recommendation,
        "risk": result.risk,
        "artifacts": [a.model_dump() for a in result.artifacts],
        "findings": result.findings or {},
        "error": result.error,
        "message": result.message,
        "preflight": {
            "path": path_hint,
            "ready": pf.get("ready"),
            "score": ((pf.get("platforms") or {}).get(plat) or {}).get("score"),
            "missing": ((pf.get("platforms") or {}).get(plat) or {}).get("missing"),
            "fixable": pf.get("fixable"),
            "install_hints": pf.get("install_hints"),
            "next_steps": pf.get("next_steps"),
        },
    }
    if isinstance(out["findings"], dict):
        out["findings"] = {**out["findings"], "preflight_ready": pf.get("ready")}
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


__all__ = ["call_tool", "tools_catalog", "tool_schema"]
