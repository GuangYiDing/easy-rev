"""Case initialization and ACT guard (scope gate)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from easy_rev.skill.evidence import ensure_ops_scaffold
from easy_rev.skill.journal import ensure_journal_scaffold, journal_search
from easy_rev.skill.routing import master_route
from easy_rev.skill.scope import default_scope, evaluate_scope, load_scope, write_scope


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff_-]+", "-", (text or "").strip().lower())
    s = re.sub(r"-+", "-", s).strip("-")
    return (s or "case")[:40]


def case_init(
    *,
    hint: str = "",
    case_name: str | None = None,
    dest: str | Path | None = None,
    platform: str | None = None,
    auth_granted: bool = False,
    auth_basis: str = "unknown",
    network_profile: str = "offline",
    target: str | None = None,
    assets: list[str] | None = None,
    with_pack: bool = True,
    with_hooks: bool = False,
    notes: str = "",
) -> dict[str, Any]:
    """Create a case directory with scope + evidence scaffold (+ optional pack)."""
    route = master_route(hint or case_name or "general reverse", platform=platform)
    plat = platform or route.get("platform") or "web"
    day = datetime.now(UTC).strftime("%Y%m%d")
    name = case_name or _slug(hint or f"case-{plat}")
    case_id = f"{day}-{name}"

    if dest:
        root = Path(dest).expanduser().resolve()
    else:
        root = Path("packs") / name

    root.mkdir(parents=True, exist_ok=True)
    in_assets = list(assets or [])
    if target and target not in in_assets:
        in_assets.insert(0, target)

    scope = default_scope(
        case_id=case_id,
        primary=str(route.get("primary") or "general-re"),
        platform=str(plat),
        auth_status="granted" if auth_granted else "pending",
        auth_basis=auth_basis,
        network_profile=network_profile,
        in_scope_assets=in_assets,
        notes=notes or hint,
    )
    # If granted + assets, mark ready
    gate = evaluate_scope(scope)
    scope["signoff"]["ready_for_act"] = bool(gate.get("ready"))
    scope_path = write_scope(root, scope)
    ops = ensure_ops_scaffold(root)
    journal = ensure_journal_scaffold()

    pack_info: dict[str, Any] | None = None
    if with_pack and not (root / "pack.yaml").is_file():
        from easy_rev.pack.template import init_pack

        init_pack(
            root,
            pack_id=name,
            name=name,
            description=hint or name,
            platform=str(plat),
            with_hooks=with_hooks,
            with_ops=False,  # already created
        )
        pack_info = {"path": str(root), "pack_id": name}

    # similar past journal hits
    similar = journal_search(hint or name, platform=str(plat) if plat else None, limit=5)

    # timeline
    tl = root / "timeline.md"
    ts = datetime.now(UTC).replace(microsecond=0).isoformat()
    line = (
        f"- {ts} case.init route={route.get('route_id')} "
        f"primary={route.get('primary')}\n"
    )
    if tl.is_file():
        text = tl.read_text(encoding="utf-8")
        if not text.endswith("\n"):
            text += "\n"
        tl.write_text(text + line, encoding="utf-8")
    else:
        tl.write_text("# Timeline\n\n" + line, encoding="utf-8")

    return {
        "ok": True,
        "case_id": case_id,
        "path": str(root),
        "scope_path": str(scope_path),
        "route": route,
        "scope": scope,
        "gate": gate,
        "ops": ops,
        "journal_root": journal.get("root"),
        "similar_journal": similar.get("hits") or [],
        "pack": pack_info,
        "next_steps": [
            "若 auth 未 granted：补授权材料后更新 scope.yaml",
            "case.guard 确认 ready 后再 explore/attach",
            f"PRIMARY tools: {', '.join((route.get('tools') or [])[:5])}",
            "任务结束：evidence + findings + journal.write（脱敏）",
        ],
    }


def case_guard(root: str | Path, *, force: bool = False) -> dict[str, Any]:
    """Check whether ACT is allowed for this case/pack."""
    root_p = Path(root).expanduser().resolve()
    scope = load_scope(root_p)
    gate = evaluate_scope(scope)
    result = {
        **gate,
        "path": str(root_p),
        "force": force,
        "scope_present": scope is not None,
    }
    if force and not gate.get("ready"):
        result["ready"] = True
        result["status"] = "forced"
        result["warning"] = "forced ready despite blocking issues — operator assumes risk"
        result["blocking_issues"] = list(gate.get("blocking_issues") or [])
    # exit-code style for CLI
    result["exit_code"] = 0 if result.get("ready") else 2
    return result
