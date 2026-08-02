"""Validate a Target Pack directory for structural readiness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def validate_pack(path: str | Path) -> dict[str, Any]:
    """Check pack.yaml / playbook / hooks existence and basic schema fields."""
    root = Path(path).expanduser().resolve()
    errors: list[str] = []
    warnings: list[str] = []
    info: dict[str, Any] = {"path": str(root)}

    if not root.is_dir():
        return {"ok": False, "errors": [f"not a directory: {root}"], "warnings": [], "info": info}

    pack_yaml = root / "pack.yaml"
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
    if not playbook.is_file():
        # some packs may use flow.yaml only (from_capture)
        flow = root / "flow.yaml"
        if flow.is_file():
            info["playbook"] = "flow.yaml"
            warnings.append("no playbook.yaml; flow.yaml present (protocol pack style)")
        else:
            errors.append("missing playbook.yaml (and no flow.yaml)")
    else:
        try:
            pb = yaml.safe_load(playbook.read_text(encoding="utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            errors.append(f"playbook.yaml parse error: {e}")
            pb = {}
        steps = pb.get("steps") if isinstance(pb, dict) else None
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
    if hooks_py.is_file():
        info["hooks"] = "hooks.py"
    elif hooks_dir.is_dir():
        js = sorted(p.name for p in hooks_dir.glob("*.js"))
        info["hooks"] = js
        if not js:
            warnings.append("hooks/ is empty")
    else:
        warnings.append("no hooks.py or hooks/ (ok for pure protocol packs)")

    readme = root / "README.md"
    if not readme.is_file():
        warnings.append("missing README.md")

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "info": info,
    }
