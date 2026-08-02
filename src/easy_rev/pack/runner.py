"""Execute / dry-run a Target Pack playbook or flow.yaml."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from easy_rev.pack.validate import validate_pack


def _load_steps(root: Path) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    """Return (steps, source_name, vars)."""
    pb = root / "playbook.yaml"
    flow = root / "flow.yaml"
    pack_meta: dict[str, Any] = {}
    pack_yaml = root / "pack.yaml"
    if pack_yaml.is_file():
        pack_meta = yaml.safe_load(pack_yaml.read_text(encoding="utf-8")) or {}

    if pb.is_file():
        data = yaml.safe_load(pb.read_text(encoding="utf-8")) or {}
        steps = list(data.get("steps") or [])
        variables = dict(data.get("vars") or {})
        return steps, "playbook.yaml", {**variables, "_pack": pack_meta}

    if flow.is_file():
        data = yaml.safe_load(flow.read_text(encoding="utf-8")) or {}
        # protocol flow may use steps or list of http.request
        if isinstance(data, dict):
            steps = list(data.get("steps") or data.get("flow") or [])
            variables = dict(data.get("vars") or {})
        elif isinstance(data, list):
            steps = data
            variables = {}
        else:
            steps, variables = [], {}
        return steps, "flow.yaml", {**variables, "_pack": pack_meta}

    return [], "", {"_pack": pack_meta}


def _resolve_action(step: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """Map playbook step → (tool_name, tool_args)."""
    action = step.get("action") or step.get("op") or step.get("type")
    args = {k: v for k, v in step.items() if k not in {"id", "action", "op", "type", "name"}}
    if not action:
        # bare http.request style
        if step.get("method") and step.get("url"):
            return "web.offline_chain", {"capture": {"apis": [step]}, "write_pack": False}
        return None, args

    action = str(action)
    # alias map
    aliases = {
        "web.explore": "web.explore",
        "web.auto_sign": "web.analyze_js",
        "web.capture": "web.capture",
        "desktop.static": "analyze",
        "desktop.attach": "desktop.explore",
        "desktop.dump": "desktop.scripts",
        "mobile.static": "analyze",
        "mobile.spawn": "mobile.explore",
        "mobile.dump": "mobile.scripts",
        "http.request": None,  # dry record only
        "artifact.export": None,
        "pack.from_capture": "pack.from_capture",
        "pack.validate": "pack.validate",
        "doctor": "doctor",
        "explore": "explore",
        "analyze": "analyze",
    }
    tool = aliases.get(action, action if action in {
        "doctor", "explore", "capture", "analyze",
        "web.explore", "web.capture", "web.analyze_js", "web.offline_chain",
        "web.diagnose", "web.har_export", "web.dependency_graph",
        "desktop.explore", "desktop.ps", "desktop.scripts",
        "mobile.explore", "mobile.devices", "mobile.apps", "mobile.scripts",
        "pack.init", "pack.list", "pack.from_capture", "pack.validate",
        "frida.session.start", "frida.session.list",
    } else None)

    # normalize args for analyze/explore
    if tool == "analyze":
        if "binary" in args and "platform" not in args:
            # infer from pack later
            pass
        args.setdefault("platform", args.get("platform") or "web")
    if tool == "desktop.explore":
        args.setdefault("platform", "macos")
    if tool == "mobile.explore":
        args.setdefault("platform", "android")
    if tool is None and action == "http.request":
        return None, {"_http_request": args}
    return tool, args


def _render_vars(value: Any, variables: dict[str, Any]) -> Any:
    """Very small {{ vars.x }} interpolator for strings."""
    if isinstance(value, str) and "{{" in value:
        out = value
        for k, v in variables.items():
            if k.startswith("_"):
                continue
            out = out.replace(f"{{{{ vars.{k} }}}}", str(v))
            out = out.replace(f"{{{{vars.{k}}}}}", str(v))
        return out
    if isinstance(value, dict):
        return {k: _render_vars(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_vars(v, variables) for v in value]
    return value


async def run_pack(
    path: str | Path,
    *,
    dry_run: bool = True,
    vars_override: dict[str, Any] | None = None,
    max_steps: int = 20,
) -> dict[str, Any]:
    """Validate then execute playbook steps.

    dry_run=True (default): map steps and return plan without calling network/frida tools
    that require live targets. Still runs pure local tools (validate, diagnose file, etc.).
    """
    root = Path(path).expanduser().resolve()
    validation = validate_pack(root)
    if not validation.get("ok"):
        return {
            "ok": False,
            "error": "pack validation failed",
            "validation": validation,
        }

    steps, source, variables = _load_steps(root)
    if vars_override:
        variables.update(vars_override)
    pack_meta = variables.get("_pack") or {}
    platform = pack_meta.get("platform") or "web"

    results: list[dict[str, Any]] = []
    for i, raw_step in enumerate(steps[:max_steps]):
        if not isinstance(raw_step, dict):
            results.append({"index": i, "ok": False, "error": "step is not a mapping"})
            continue
        step = _render_vars(raw_step, variables)
        tool, args = _resolve_action(step)
        step_id = step.get("id") or f"step_{i}"
        rec: dict[str, Any] = {
            "index": i,
            "id": step_id,
            "action": step.get("action") or step.get("op"),
            "tool": tool,
            "args": {k: v for k, v in args.items() if not str(k).startswith("_")},
        }

        # inject platform defaults
        if tool in {"analyze", "explore", "capture"} and "platform" not in args:
            args = {**args, "platform": platform if platform != "desktop" else "macos"}
            rec["args"] = {k: v for k, v in args.items() if not str(k).startswith("_")}

        if dry_run:
            # only execute purely local safe tools
            local_ok = tool in {
                "doctor",
                "pack.validate",
                "pack.list",
                "desktop.scripts",
                "mobile.scripts",
                "web.diagnose",
            }
            if tool == "pack.validate":
                args = {**args, "path": str(root)}
            if tool and local_ok:
                from easy_rev.ai.handlers import call_tool

                out = await call_tool(tool, args)
                rec["result"] = out
                rec["ok"] = bool(out.get("ok"))
                rec["mode"] = "executed_local"
            elif tool is None and "_http_request" in args:
                rec["ok"] = True
                rec["mode"] = "dry_run"
                rec["result"] = {
                    "ok": True,
                    "status": "dry_run",
                    "message": "http.request not executed in dry_run",
                    "request": args.get("_http_request"),
                }
            else:
                rec["ok"] = True
                rec["mode"] = "dry_run"
                rec["result"] = {
                    "ok": True,
                    "status": "dry_run",
                    "message": f"would call {tool}",
                    "tool": tool,
                    "args": rec["args"],
                }
        else:
            if tool is None and "_http_request" in args:
                # minimal http replay
                req = args.get("_http_request") or {}
                rec["result"] = await _http_replay(req)
                rec["ok"] = bool(rec["result"].get("ok"))
                rec["mode"] = "http_replay"
            elif tool is None:
                rec["ok"] = False
                rec["mode"] = "skipped"
                rec["error"] = f"unmapped action: {step.get('action')}"
            else:
                from easy_rev.ai.handlers import call_tool

                if tool == "pack.validate":
                    args = {**args, "path": str(root)}
                out = await call_tool(tool, args)
                rec["result"] = out
                rec["ok"] = bool(out.get("ok"))
                rec["mode"] = "executed"

        results.append(rec)

    ok = all(r.get("ok") for r in results) if results else validation.get("ok")
    summary = {
        "ok": bool(ok),
        "path": str(root),
        "source": source,
        "dry_run": dry_run,
        "platform": platform,
        "step_count": len(results),
        "executed": sum(1 for r in results if r.get("mode") in {"executed", "executed_local", "http_replay"}),
        "dry_planned": sum(1 for r in results if r.get("mode") == "dry_run"),
        "steps": results,
        "validation": validation,
    }
    # persist report
    report_path = root / ("run-dry-report.json" if dry_run else "run-report.json")
    try:
        report_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        summary["report_path"] = str(report_path)
    except Exception:  # noqa: BLE001
        pass
    return summary


async def _http_replay(req: dict[str, Any]) -> dict[str, Any]:
    """Minimal httpx replay for flow http.request steps."""
    import httpx

    method = str(req.get("method") or "GET").upper()
    url = req.get("url")
    if not url:
        return {"ok": False, "error": "url required"}
    headers = req.get("headers") or req.get("request_headers") or {}
    body = req.get("body") or req.get("post_data")
    timeout = float(req.get("timeout_s") or 30)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.request(method, url, headers=headers, content=body)
        return {
            "ok": True,
            "status_code": r.status_code,
            "url": str(r.url),
            "headers": dict(r.headers),
            "body_preview": r.text[:2000],
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "url": url, "method": method}
