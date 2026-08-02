"""Scope contract: authorization + network profile gate before target ACT."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

AUTH_STATUSES = {"granted", "pending", "denied"}
NETWORK_PROFILES = {
    "offline",
    "lab_only",
    "authorized_target_only",
    "unrestricted_lab",
}
AUTH_BASIS = {
    "own_system",
    "written_contract",
    "bug_bounty",
    "ctf_public",
    "lab_only",
    "unknown",
}


def default_scope(
    *,
    case_id: str,
    primary: str = "general-re",
    platform: str | None = None,
    auth_status: str = "pending",
    auth_basis: str = "unknown",
    network_profile: str = "offline",
    in_scope_assets: list[str] | None = None,
    out_of_scope: list[str] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    assets = list(in_scope_assets or [])
    ready = auth_status == "granted" and bool(assets or network_profile == "offline")
    return {
        "schema": "easy-rev.scope/v1",
        "meta": {
            "case_id": case_id,
            "created": now,
            "primary_skill": primary,
            "platform": platform,
            "lead_role": "lead",
            "specialist_roles": [],
        },
        "auth": {
            "status": auth_status if auth_status in AUTH_STATUSES else "pending",
            "basis": auth_basis if auth_basis in AUTH_BASIS else "unknown",
            "evidence_of_auth": notes or "",
        },
        "in_scope": {
            "assets": assets,
            "surfaces": [platform] if platform else [],
            "activities": ["recon", "reverse", "pack", "report"],
        },
        "out_of_scope": {
            "assets": list(out_of_scope or []),
            "activities": ["dos", "phishing_real_users", "data_exfil", "credential_theft"],
        },
        "network_profile": {
            "mode": network_profile if network_profile in NETWORK_PROFILES else "offline",
            "notes": notes,
        },
        "deliverables": {
            "report": True,
            "field_journal": True,
            "evidence": True,
            "timeline": True,
            "pack": True,
        },
        "constraints": {
            "stealth": "low",
            "data_handling": "anonymize",
        },
        "signoff": {
            "ready_for_act": ready,
            "checklist": {
                "auth_granted": auth_status == "granted",
                "assets_or_offline": bool(assets) or network_profile == "offline",
                "network_profile_set": network_profile in NETWORK_PROFILES,
                "out_of_scope_reviewed": True,
            },
        },
    }


def load_scope(root: str | Path) -> dict[str, Any] | None:
    root_p = Path(root).expanduser().resolve()
    for name in ("scope.yaml", "scope.md"):
        path = root_p / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if name.endswith(".yaml"):
            data = yaml.safe_load(text) or {}
            return data if isinstance(data, dict) else None
        return _parse_scope_md(text)
    pack_yaml = root_p / "pack.yaml"
    if pack_yaml.is_file():
        meta = yaml.safe_load(pack_yaml.read_text(encoding="utf-8")) or {}
        if isinstance(meta, dict) and isinstance(meta.get("scope"), dict):
            return meta["scope"]
    return None


def write_scope(root: str | Path, scope: dict[str, Any]) -> Path:
    root_p = Path(root).expanduser().resolve()
    root_p.mkdir(parents=True, exist_ok=True)
    path = root_p / "scope.yaml"
    path.write_text(
        yaml.safe_dump(scope, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return path


def evaluate_scope(scope: dict[str, Any] | None, *, require_assets: bool = True) -> dict[str, Any]:
    """Return gate decision. ready=True only when ACT against target is allowed."""
    if not scope:
        return {
            "ok": True,
            "ready": False,
            "status": "missing_scope",
            "blocking_issues": [
                "missing scope.yaml — run case.init or write skills/ops/scope-contract.md template"
            ],
            "allowed": ["read_docs", "route", "doctor", "static_offline"],
            "forbidden": ["attach", "hook", "network_act", "pack.run_execute"],
        }

    auth = scope.get("auth") if isinstance(scope.get("auth"), dict) else {}
    net = scope.get("network_profile") if isinstance(scope.get("network_profile"), dict) else {}
    in_scope = scope.get("in_scope") if isinstance(scope.get("in_scope"), dict) else {}
    signoff = scope.get("signoff") if isinstance(scope.get("signoff"), dict) else {}

    status = str(auth.get("status") or "pending").lower()
    mode = str(net.get("mode") or "").lower()
    assets = list(in_scope.get("assets") or [])
    blocking: list[str] = []

    if status != "granted":
        blocking.append(f"auth.status={status} (need granted)")
    if mode not in NETWORK_PROFILES:
        blocking.append("network_profile.mode missing or invalid")
    if require_assets and mode != "offline" and not assets:
        blocking.append("in_scope.assets empty while network_profile is not offline")

    # honor explicit ready_for_act=false when present and other fields already ok
    if signoff.get("ready_for_act") is False and not blocking:
        blocking.append("signoff.ready_for_act=false")

    ready = len(blocking) == 0
    return {
        "ok": True,
        "ready": ready,
        "status": "ready" if ready else "blocked",
        "auth_status": status,
        "network_profile": mode or None,
        "assets": assets,
        "blocking_issues": blocking,
        "allowed": (
            [
                "read_docs",
                "route",
                "doctor",
                "static_offline",
                "attach",
                "hook",
                "network_act",
                "pack.run_execute",
            ]
            if ready
            else ["read_docs", "route", "doctor", "static_offline", "case.init"]
        ),
        "forbidden": [] if ready else ["attach", "hook", "network_act", "pack.run_execute"],
        "hint": (
            "scope ready — may ACT on in_scope assets only"
            if ready
            else "fix auth/network_profile/assets then re-run case.guard"
        ),
    }


def _parse_scope_md(text: str) -> dict[str, Any]:
    """Best-effort parse of markdown scope template."""
    status = "pending"
    basis = "unknown"
    mode = "offline"
    assets: list[str] = []
    case_id = "unknown"
    for line in text.splitlines():
        s = line.strip().lstrip("-").strip()
        low = s.lower()
        if low.startswith("status:"):
            status = s.split(":", 1)[1].strip().split()[0]
        elif low.startswith("basis:"):
            basis = s.split(":", 1)[1].strip().split()[0]
        elif low.startswith("mode:"):
            mode = s.split(":", 1)[1].strip().split()[0]
        elif low.startswith("case_id:"):
            case_id = s.split(":", 1)[1].strip()
        elif low.startswith("assets:"):
            rest = s.split(":", 1)[1].strip()
            if rest.startswith("["):
                try:
                    assets = list(yaml.safe_load(rest) or [])
                except Exception:  # noqa: BLE001
                    pass
    return default_scope(
        case_id=case_id,
        auth_status=status,
        auth_basis=basis,
        network_profile=mode,
        in_scope_assets=assets,
    )
