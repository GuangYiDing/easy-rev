"""Validate a Target Pack directory for structural and semantic readiness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# Actions the pack runner knows how to map
KNOWN_ACTIONS = {
    "web.explore",
    "web.auto_sign",
    "web.capture",
    "web.analyze_js",
    "web.offline_chain",
    "web.diagnose",
    "web.har_export",
    "web.dependency_graph",
    "desktop.static",
    "desktop.attach",
    "desktop.dump",
    "desktop.explore",
    "desktop.ps",
    "desktop.scripts",
    "mobile.static",
    "mobile.spawn",
    "mobile.dump",
    "mobile.explore",
    "mobile.devices",
    "mobile.apps",
    "mobile.scripts",
    "http.request",
    "artifact.export",
    "pack.from_capture",
    "pack.validate",
    "doctor",
    "explore",
    "analyze",
    "capture",
    "frida.session.start",
    "frida.session.list",
}


def validate_pack(path: str | Path, *, semantic: bool = True) -> dict[str, Any]:
    """Check pack.yaml / playbook / hooks existence and basic schema fields.

    semantic=True also checks playbook step actions and referenced hook files.
    """
    root = Path(path).expanduser().resolve()
    errors: list[str] = []
    warnings: list[str] = []
    info: dict[str, Any] = {"path": str(root)}

    if not root.is_dir():
        return {"ok": False, "errors": [f"not a directory: {root}"], "warnings": [], "info": info}

    pack_yaml = root / "pack.yaml"
    meta: dict[str, Any] = {}
    if not pack_yaml.is_file():
        errors.append("missing pack.yaml")
    else:
        try:
            meta = yaml.safe_load(pack_yaml.read_text(encoding="utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            errors.append(f"pack.yaml parse error: {e}")
            meta = {}
        if not isinstance(meta, dict):
            errors.append("pack.yaml root must be a mapping")
            meta = {}
        info["pack"] = {
            "id": meta.get("id"),
            "name": meta.get("name"),
            "platform": meta.get("platform"),
            "schema": meta.get("schema"),
        }
        for req in ("id", "platform", "schema"):
            if not meta.get(req):
                errors.append(f"pack.yaml missing field: {req}")
        schema = str(meta.get("schema") or "")
        if schema and "easy-rev.pack" not in schema:
            warnings.append(f"unexpected schema: {schema}")

    playbook = root / "playbook.yaml"
    steps: list[Any] = []
    if not playbook.is_file():
        # some packs may use flow.yaml only (from_capture)
        flow = root / "flow.yaml"
        if flow.is_file():
            info["playbook"] = "flow.yaml"
            warnings.append("no playbook.yaml; flow.yaml present (protocol pack style)")
            try:
                flow_data = yaml.safe_load(flow.read_text(encoding="utf-8")) or {}
            except Exception as e:  # noqa: BLE001
                errors.append(f"flow.yaml parse error: {e}")
                flow_data = {}
            if isinstance(flow_data, dict):
                steps = list(flow_data.get("steps") or flow_data.get("flow") or [])
            elif isinstance(flow_data, list):
                steps = flow_data
            info["step_count"] = len(steps)
        else:
            errors.append("missing playbook.yaml (and no flow.yaml)")
    else:
        try:
            pb = yaml.safe_load(playbook.read_text(encoding="utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            errors.append(f"playbook.yaml parse error: {e}")
            pb = {}
        steps = list(pb.get("steps") or []) if isinstance(pb, dict) else []
        if not steps:
            warnings.append("playbook.yaml has no steps")
        else:
            info["step_count"] = len(steps)
            info["actions"] = [
                s.get("action") for s in steps if isinstance(s, dict) and s.get("action")
            ][:20]

    # hooks
    hooks_py = root / "hooks.py"
    hooks_dir = root / "hooks"
    hook_files: list[str] = []
    if hooks_py.is_file():
        info["hooks"] = "hooks.py"
        hook_files.append("hooks.py")
    elif hooks_dir.is_dir():
        js = sorted(p.name for p in hooks_dir.glob("*.js"))
        info["hooks"] = js
        hook_files.extend(f"hooks/{name}" for name in js)
        if not js:
            warnings.append("hooks/ is empty")
    else:
        warnings.append("no hooks.py or hooks/ (ok for pure protocol packs)")

    readme = root / "README.md"
    if not readme.is_file():
        warnings.append("missing README.md")

    # ops / scope (absorbed from reverse-skill style contracts)
    scope_yaml = root / "scope.yaml"
    if scope_yaml.is_file():
        try:
            scope = yaml.safe_load(scope_yaml.read_text(encoding="utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            warnings.append(f"scope.yaml parse error: {e}")
            scope = {}
        info["scope"] = {
            "auth": (scope.get("auth") or {}).get("status") if isinstance(scope, dict) else None,
            "network_profile": (
                (scope.get("network_profile") or {}).get("mode")
                if isinstance(scope, dict)
                else None
            ),
            "ready_for_act": (
                (scope.get("signoff") or {}).get("ready_for_act")
                if isinstance(scope, dict)
                else None
            ),
        }
        if isinstance(scope, dict):
            auth_st = str((scope.get("auth") or {}).get("status") or "").lower()
            if auth_st != "granted":
                warnings.append(
                    f"scope.auth.status={auth_st or 'missing'} — ACT blocked until granted"
                )
    else:
        warnings.append("missing scope.yaml (run case.init / pack.init with ops)")

    if not (root / "findings.md").is_file():
        warnings.append("missing findings.md (evidence chain incomplete)")
    if not (root / "evidence").is_dir():
        warnings.append("missing evidence/ directory")

    if semantic and steps:
        unknown_actions: list[str] = []
        missing_script_refs: list[str] = []
        platform = str((meta or {}).get("platform") or "").lower()
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"step[{i}] is not a mapping")
                continue
            action = step.get("action") or step.get("op") or step.get("type")
            # bare http.request style
            if not action and step.get("method") and step.get("url"):
                action = "http.request"
            if not action:
                warnings.append(f"step[{i}] has no action/op/type")
                continue
            action_s = str(action)
            if action_s not in KNOWN_ACTIONS:
                unknown_actions.append(action_s)
            # platform consistency soft-check
            if platform in {"web"} and action_s.startswith(("desktop.", "mobile.")):
                warnings.append(f"step[{i}] action {action_s} looks non-web on web pack")
            if platform in {"desktop", "windows", "macos"} and action_s.startswith("mobile."):
                warnings.append(f"step[{i}] action {action_s} looks mobile on desktop pack")
            if platform in {"mobile", "android", "ios"} and action_s.startswith("desktop."):
                warnings.append(f"step[{i}] action {action_s} looks desktop on mobile pack")
            # script path existence
            scripts = step.get("scripts") or []
            if isinstance(scripts, str):
                scripts = [scripts]
            for rel in scripts:
                if not isinstance(rel, str):
                    continue
                # allow absolute or pack-relative
                candidate = Path(rel)
                if not candidate.is_absolute():
                    candidate = root / rel
                if not candidate.is_file():
                    missing_script_refs.append(rel)
        if unknown_actions:
            # unknown is warning (custom tools) not hard error
            warnings.append(
                "unknown playbook actions (runner may skip): "
                + ", ".join(sorted(set(unknown_actions))[:12])
            )
        if missing_script_refs:
            warnings.append(
                "playbook scripts not found in pack: "
                + ", ".join(sorted(set(missing_script_refs))[:12])
            )
        info["semantic"] = {
            "known_action_count": sum(
                1
                for s in steps
                if isinstance(s, dict)
                and str(s.get("action") or s.get("op") or s.get("type") or "") in KNOWN_ACTIONS
            ),
            "hook_files": hook_files,
        }

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "info": info,
    }
